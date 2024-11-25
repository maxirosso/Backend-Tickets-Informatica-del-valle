const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Imap = require('imap');
const { simpleParser } = require('mailparser');
const cron = require('node-cron');
const { v4: uuidv4 } = require('uuid');

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors());

// MongoDB setup
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => console.log("MongoDB connection error:", err));

// Ticket model (added messageId field to match emails)
const ticketSchema = new mongoose.Schema({
  subject: { type: String, required: true },
  sender: { type: String, required: true },
  content: { type: String, required: true },
  date: { type: Date, default: Date.now },
  messageId: { type: String, required: true }, // Unique ID of the original email message
  inReplyTo: { type: String }, // ID of the message this one is in reply to
  references: { type: [String], default: [] }, // Array of messageIds in the conversation thread
  status: {
    type: String,
    enum: ['Pendiente', 'En Proceso', 'Resuelto'],
    default: 'Pendiente', // Default status for a new ticket
  },
  history: [
    {
      content: { type: String, required: true },
      date: { type: Date, default: Date.now },
      sender: { type: String, required: true },
      messageId: { type: String, required: true }, // Unique ID for this specific history message
      inReplyTo: { type: String }, // messageId of the previous message in the thread
      references: { type: [String], default: [] }, // Array of messageIds up to this point in the conversation
    },
  ],
});

const Ticket = mongoose.model('Ticket', ticketSchema);

// User model for authentication
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Authentication middleware
const auth = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Access denied' });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ message: 'Invalid token' });
  }
};

// Route to register a new user
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error registering user' });
  }
});

// Route to log in a user
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    
    // Return username and token along with the success message
    res.status(200).json({
      message: 'Login successful',
      token,
      username: user.username,  // Include the username in the response
    });
  } catch (err) {
    res.status(500).json({ message: 'Error logging in user' });
  }
});

// Route to fetch tickets
app.get('/tickets', auth, async (req, res) => {
  try {
    const tickets = await Ticket.find().lean();

    // Only send the latest message if history exists and include inReplyTo and references
    const modifiedTickets = tickets.map(ticket => {
      if (ticket.history && ticket.history.length > 0) {
        // Show last reply only, but also include inReplyTo and references from the latest history message
        const lastHistory = ticket.history[ticket.history.length - 1];
        return {
          ...ticket,
          content: lastHistory.content,    // Show last reply only
          historyCount: ticket.history.length,  // Add history count to check in the frontend
          inReplyTo: lastHistory.inReplyTo,    // Include inReplyTo from the last history message
          references: lastHistory.references, // Include references from the last history message
        };
      }
      return ticket;
    });

    res.json(modifiedTickets);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching tickets' });
  }
});


// Route to save a ticket (insert new tickets into MongoDB)
app.post('/tickets', auth, async (req, res) => {
  const { subject, sender, content, inReplyTo, references } = req.body;

  try {
    // Clean the sender to only capture the email address, not the name
    const cleanedSender = sender.includes('<') ? sender.split('<')[1].replace('>', '') : sender;

    // Optionally, clean the content to handle any HTML, embedded images, etc.
    const cleanedContent = content.replace(/<\/?[^>]+(>|$)/g, "");  // Removes HTML tags

    // Generate a new messageId for the ticket or reply (for new tickets)
    const messageId = uuidv4(); 

    // Assign default values if not provided in the request
    const finalInReplyTo = inReplyTo || null; // If inReplyTo is not provided, set to null
    const finalReferences = references ? references.split(' ') : []; // Split references if provided, otherwise empty array
    const status = "Pendiente"; // Default status for new tickets

    let ticket;

    // Try to find a matching ticket based on inReplyTo or references
    if (inReplyTo) {
      // Find ticket by inReplyTo (e.g., if this is a reply to an existing ticket)
      ticket = await Ticket.findOne({
        $or: [
          { messageId: inReplyTo },       // Check if the inReplyTo is the main messageId
          { 'history.messageId': inReplyTo } // Check if the inReplyTo is in the ticket history
        ],
      });
    }

    if (!ticket && references) {
      // If no ticket found, check references (could be multiple references)
      const referenceIds = references.split(' ');
      ticket = await Ticket.findOne({
        $or: [
          { messageId: { $in: referenceIds } },      // Check references in the main messageId
          { 'history.messageId': { $in: referenceIds } }, // Check references in the history
        ],
      });
    }

    if (ticket) {
      // If a matching ticket is found, add the new message to the history
      ticket.history.push({
        content: cleanedContent,  // Use the cleaned content
        date: new Date(),
        sender: cleanedSender,    // Use the cleaned sender (email only)
        messageId,               // Ensure the messageId is unique and correctly assigned
        inReplyTo: finalInReplyTo, // This links the reply to the original message
        references: finalReferences, // Maintain references
      });
      await ticket.save();
      return res.status(200).json({ message: 'Ticket updated successfully', ticket });
    } else {
      // If no ticket found, create a new ticket (fallback)
      const newTicket = new Ticket({
        subject,
        sender: cleanedSender,  // Store only the email address, not the name
        content: cleanedContent, // Clean the content to remove any HTML
        messageId,              // The first message's unique ID
        inReplyTo: finalInReplyTo, // Assign finalInReplyTo (null if not provided)
        references: finalReferences, // Assign references (empty array if not provided)
        status,  // Default status for new tickets
        history: []  // Initialize history as an empty array for the first message
      });
      await newTicket.save();
      return res.status(201).json({ message: 'Ticket saved successfully', ticket: newTicket });
    }
  } catch (err) {
    console.error('Error saving or updating ticket:', err);
    res.status(500).json({ message: 'Error saving or updating ticket' });
  }
});






// Route to reply to a ticket
 // Ensure you have the UUID library imported

 app.post('/tickets/reply', auth, async (req, res) => {
  const { ticketId, replyMessage, messageId, inReplyTo, references, status } = req.body;

  try {
    // Validar que ticketId y replyMessage estén presentes
    if (!ticketId || !replyMessage) {
      return res.status(400).json({ message: "Ticket ID y mensaje de respuesta son requeridos." });
    }

    // Validar que messageId esté presente
    if (!messageId) {
      return res.status(400).json({ message: "messageId es requerido." });
    }

    // Buscar el ticket por ID
    const ticket = await Ticket.findById(ticketId);
    if (!ticket) {
      return res.status(404).json({ message: "Ticket no encontrado" });
    }

    // Construir el nuevo objeto de respuesta
    const newReply = {
      content: replyMessage,
      date: new Date(),
      sender: req.user.username || "System", // Asignar el remitente
      messageId, // Usar el messageId proporcionado
      inReplyTo: inReplyTo || null,
      references: references || ticket.references || [], // Usar referencias si se pasan
    };

    // Verificar que el messageId esté presente en el objeto newReply
    console.log("Nuevo mensaje de respuesta:", newReply);

    // Agregar la respuesta al historial del ticket
    ticket.history.push(newReply);

    // Verificar el historial del ticket antes de guardarlo
    console.log("Historial del ticket antes de guardar:", ticket.history);

    // Establecer el estado del ticket (si es necesario)
    ticket.status = status || "Pendiente"; // Usar el status proporcionado o por defecto "Pendiente"

    // Guardar el ticket con el historial actualizado
    const updatedTicket = await ticket.save();

    // Enviar correo electrónico si es necesario
    const transporter = nodemailer.createTransport({
      host: "mr.fibercorp.com.ar",
      port: 465,
      secure: true,
      auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD,
      },
      tls: { rejectUnauthorized: false },
    });

    const mailOptions = {
      from: process.env.EMAIL,
      to: ticket.sender,
      subject: `Re: ${ticket.subject}`,
      text: `Has recibido una nueva respuesta: \n\n${replyMessage}`,
    };

    await transporter.sendMail(mailOptions);

    // Responder con el ticket actualizado
    res.status(200).json(updatedTicket);
  } catch (err) {
    console.error("Error al responder al ticket:", err.message);
    res.status(500).json({ message: "Error al responder al ticket", error: err.message });
  }
});






app.get('/tickets/:id/history', auth, async (req, res) => {
  const { id } = req.params;
  
  try {
    const ticket = await Ticket.findById(id);
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }

    res.json(ticket.history);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching ticket history' });
  }
});


// Route to delete a ticket
app.delete('/tickets/:id', auth, async (req, res) => {
  const { id } = req.params;

  try {
    const ticket = await Ticket.findByIdAndDelete(id);
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }
    res.status(200).json({ message: 'Ticket deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting ticket', error: err.message });
  }
});

app.post('/api/tickets/status/:id', async (req, res) => {
  const { id } = req.params;
  const { status } = req.body; // 'pendiente', 'resuelto', or 'en proceso'

  // Validate the status
  if (!['pendiente', 'resuelto', 'en proceso'].includes(status)) {
    return res.status(400).json({ message: 'Invalid status value.' });
  }

  try {
    // Find the ticket by ID and update the status
    const ticket = await Ticket.findByIdAndUpdate(
      id,
      { status },
      { new: true } // Return the updated ticket
    );

    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found.' });
    }

    // Determine if the buttons should remain visible
    const canShowHistorialButtons = true; // Set this based on your desired logic

    // Respond with the updated ticket and visibility status
    res.json({
      ticket,
      canShowHistorialButtons, // Explicitly include this flag for frontend handling
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});



app.put('/tickets/:id/reply', auth, async (req, res) => {
  const { id } = req.params;
  const { replyMessage, inReplyTo, references, messageId } = req.body;

  try {
    // Validación de campos necesarios
    if (!replyMessage || !messageId) {
      return res.status(400).json({ message: "'replyMessage' and 'messageId' are required." });
    }

    // Validación del ID del ticket
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid ticket ID." });
    }

    // Buscar el ticket por ID
    const ticket = await Ticket.findById(id);
    if (!ticket) {
      return res.status(404).json({ message: "Ticket not found." });
    }

    // Inicializar historial si no existe
    if (!ticket.history) ticket.history = [];

    // Añadir la respuesta al historial del ticket
    const newReply = {
      content: replyMessage,
      date: new Date(),
      sender: req.user.username || 'System', // Garantizar que siempre haya un sender
      messageId,
      inReplyTo: inReplyTo || null,
      references: references || [],
    };

    ticket.history.push(newReply);

    // Guardar el ticket actualizado
    const updatedTicket = await ticket.save();

    // Notificación por email (si es necesario)
    const transporter = nodemailer.createTransport({
      host: 'mr.fibercorp.com.ar',
      port: 465,
      secure: true,
      auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD,
      },
      tls: {
        rejectUnauthorized: false,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL,
      to: ticket.sender,  // El remitente del ticket original
      subject: `Re: ${ticket.subject}`,
      text: `Hello,\n\nA new reply has been added to your ticket:\n\n"${replyMessage}"\n\nThank you,\nSupport Team`,
    };

    // Enviar el correo
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Error sending email:", error);
        return res.status(500).json({ message: "Reply added, but email notification failed." });
      } else {
        console.log("Email sent:", info.response);
        res.status(200).json({
          message: "Reply added successfully, and notification sent.",
          ticket: updatedTicket,
        });
      }
    });
  } catch (err) {
    if (err.name === 'ValidationError') {
      return res.status(400).json({ message: 'Validation error', errors: err.errors });
    }
    console.error("Error replying to ticket:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});








// Route to update a ticket


// IMAP connection to sync with Outlook Trash folder and delete tickets
const imap = new Imap({
  user: process.env.EMAIL,
  password: process.env.PASSWORD,
  host: 'cloudoffice.fibercorp.com.ar',
  port: 993,
  tls: true
});

// Function to connect and check Trash folder
const checkTrashFolder = () => {
  imap.once('ready', () => {
    imap.openBox('Trash', true, (err, box) => {
      if (err) {
        console.log('Error opening Trash folder:', err);
        return;
      }

      imap.search(['ALL'], async (err, results) => {
        if (err) {
          console.log('Error searching for emails:', err);
          return;
        }

        const fetch = imap.fetch(results, { bodies: '' });

        fetch.on('message', (msg, seqno) => {
          msg.on('body', async (stream) => {
            try {
              const parsed = await simpleParser(stream);
              const messageId = parsed.messageId;
              if (messageId) {
                const ticket = await Ticket.findOneAndDelete({ messageId });
                if (ticket) {
                  console.log(`Ticket ${messageId} deleted from MongoDB`);
                }
              }
            } catch (err) {
              console.log('Error parsing email:', err);
            }
          });
        });

        fetch.once('end', () => {
          imap.end();  // Close IMAP connection after fetch is done
        });
      });
    });
  });

  imap.once('error', (err) => {
    console.log('IMAP connection error:', err);
  });

  imap.connect();
};

// Cron job to sync with the Trash folder every 30 minutes
cron.schedule('*/30 * * * *', () => {
  console.log('Running IMAP sync...');
  checkTrashFolder();
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});