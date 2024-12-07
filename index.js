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
const sanitizeHtml = require('sanitize-html');


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
  messageId: { type: String, required: true, unique: true }, // Unique message ID from email
  inReplyTo: { type: String, default: null }, // Used to link to the parent email
  references: { type: [String], default: [] }, // List of related message IDs
  status: { type: String, default: 'pendiente' }, // Current status of the ticket
  history: [
    {
      content: { type: String, required: true }, // Email content
      date: { type: Date, required: true }, // Timestamp for the history entry
      sender: { type: String, required: true }, // Sender email address
      messageId: { type: String, required: true }, // Message ID of the email in history
      inReplyTo: { type: String, default: null }, // Parent message ID in history
      references: { type: [String], default: [] }, // Related message IDs for this history entry
    },
  ],
  date: { type: Date, default: Date.now }, // Creation date of the ticket
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
    const currentDate = new Date();  // Current date for the ticket creation

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
        date: currentDate,        // Use current date for the message
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
        history: [],  // History should be empty for new tickets
        date: currentDate // Set the current date when creating the ticket
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
  const { ticketId, replyMessage, messageId, status } = req.body;

  try {
    // Validate that ticketId and replyMessage are provided
    if (!ticketId || !replyMessage) {
      return res.status(400).json({ message: "Ticket ID y mensaje de respuesta son requeridos." });
    }

    // Validate that messageId is provided
    if (!messageId) {
      return res.status(400).json({ message: "messageId es requerido." });
    }

    // Find the ticket by ID
    const ticket = await Ticket.findById(ticketId);
    if (!ticket) {
      return res.status(404).json({ message: "Ticket no encontrado" });
    }

    // Determine the message to reply to
    let replyToMessage = ticket.history[0];  // Default to the first message

    // If we're replying to a specific message, use its `messageId` to find it
    if (messageId) {
      replyToMessage = ticket.history.find(msg => msg.messageId === messageId);
    }

    if (!replyToMessage) {
      return res.status(404).json({ message: "El mensaje al que estás respondiendo no se encontró en el historial." });
    }

    // Prepare inReplyTo and references fields
    const inReplyTo = replyToMessage.messageId;  // Use the original message's messageId
    const references = [inReplyTo, ...replyToMessage.references || []]; // Add previous references

    // Construct the new reply object
    const newReply = {
      content: replyMessage,
      date: new Date(),
      sender: req.user.username || "System", // Use the sender's name
      messageId: messageId || generateMessageId(), // Generate a new messageId if not provided
      inReplyTo, // Link to the original message
      references: references, // Add references to previous messages
    };

    // Add the reply to the ticket's history
    ticket.history.push(newReply);

    // Set the status of the ticket (if provided)
    ticket.status = status || "Pendiente"; // Use the status from the request or default to "Pendiente"

    // Save the updated ticket
    const updatedTicket = await ticket.save();

    // Send email notification (if necessary)
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
      headers: {
        'In-Reply-To': replyToMessage.messageId, // Message ID of the original email
        References: references.join(' '), // All message IDs in the thread, space-separated
      },
    };
    

    await transporter.sendMail(mailOptions);

    // Respond with the updated ticket
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
      text: `${replyMessage}\n\nSaludos,\nEl equipo de Informatica`,
    };

    // Enviar el correo de forma asíncrona
    await transporter.sendMail(mailOptions);

    // Responder con el ticket actualizado
    res.status(200).json({
      message: "Reply added successfully, and notification sent.",
      ticket: updatedTicket,
    });
  } catch (err) {
    if (err.name === 'ValidationError') {
      return res.status(400).json({ message: 'Validation error', errors: err.errors });
    }
    console.error("Error replying to ticket:", err);
    res.status(500).json({ message: "Internal server error", error: err.message });
  }
});



const imap = new Imap({
  user: process.env.EMAIL,
  password: process.env.PASSWORD,
  host: 'cloudoffice.fibercorp.com.ar',
  port: 993,
  tls: true,
  tlsOptions: { rejectUnauthorized: false },
  authTimeout: 10000,
});

let isConnected = false;  // Track IMAP connection status
let reconnectAttempts = 0;  // Track reconnection attempts

// Reconnection Logic
const reconnectImap = () => {
  if (isConnected) return; // Prevent reconnection if already connected
  reconnectAttempts++;

  if (reconnectAttempts > 5) {
    console.error('Max reconnection attempts reached. Please check your IMAP server connection.');
    console.log('Waiting for 5 minutes before retrying...');

    // Wait for 5 minutes (300000 ms) before retrying
    setTimeout(() => {
      reconnectAttempts = 0; // Reset reconnection attempts
      console.log('Retrying connection...');
      imap.connect();  // Attempt reconnection
    }, 300000); // 5 minutes (300,000 milliseconds)
    return;
  }

  console.log(`Reconnecting IMAP... Attempt ${reconnectAttempts}`);

  // Remove all existing event listeners to avoid duplicates
  imap.removeAllListeners();

  // Re-register IMAP event handlers
  registerImapEventHandlers();

  // Attempt reconnection after 2 seconds
  setTimeout(() => imap.connect(), 2000);
};

// Register IMAP Event Handlers
const registerImapEventHandlers = () => {
  imap.once('ready', () => {
    isConnected = true;
    reconnectAttempts = 0; // Reset reconnection attempts
    console.log('IMAP connection established');
  });

  imap.on('error', (err) => {
    console.error('IMAP connection error:', err);

    if (err.code === 'ECONNRESET') {
      console.log('Connection reset. Attempting to reconnect...');
      setTimeout(reconnectImap, 5000); // Add a delay before attempting to reconnect
    } else {
      console.error('An unexpected error occurred:', err);
    }
  });

  imap.once('close', (hadError) => {
    console.log(`IMAP connection closed${hadError ? ' due to an error' : ''}`);
    isConnected = false;
    setTimeout(reconnectImap, 5000); // Add a delay before attempting to reconnect
  });
};


// Function to clean Microsoft Word or rich-text specific tags
const cleanWordMarkup = (content) => {
  // Regular expression to remove Word-specific tags and unnecessary attributes
  const wordTagsPattern = /<w:[^>]+>|<\/w:[^>]+>/g;
  return content.replace(wordTagsPattern, '');
};

// Function to sanitize HTML (if content contains HTML) and remove any unwanted tags
const sanitizeEmailContent = (content) => {
  return sanitizeHtml(content, {
    allowedTags: [ 'b', 'i', 'u', 'strong', 'em', 'a', 'p', 'ul', 'ol', 'li', 'br', 'img' ], // List of allowed tags
    allowedAttributes: {
      'a': [ 'href', 'name', 'target' ], // Allowed attributes for <a> tags
      'img': [ 'src', 'alt' ],           // Allowed attributes for <img> tags
    },
  });
};



// Parse Sender Email Helper
const parseSender = (senderString) => {
  const parts = senderString.includes('<') ? senderString.split('<') : [senderString];
  return (parts[1] ? parts[1].replace('>', '').trim() : parts[0].trim()) || 'Unknown Sender';
};



const processedMessages = new Set();

const spanishKeywords = ["consulta", "duda", "pregunta", "ayuda", "soporte", "asistencia", "necesito ayuda", "urgente", "¿puedes ayudarme?", "¿me podrías ayudar?", "necesito saber", "¿tienes información sobre?", "favor de", "por favor", "¿cómo puedo...?", "¿qué debo hacer?", "necesito asistencia", "solicitar ayuda", "¿puedo hacer una consulta?", "¿tienes alguna solución para...?", "¿puedes orientarme?", "requerimiento", "¿puedo preguntar algo?", "¿hay alguna respuesta para...?", "problema", "atención", "reclamo", "notificación", "inconveniente", "sugerencia", "necesito información", "pregunto", "preguntar", "consulta urgente", "requiere respuesta", "me interesa saber", "me gustaría saber", "¿puedo obtener ayuda?", "solicito asistencia", "respuesta", "¿puedo obtener más detalles?", "alexis", "maximo", "ludmila"];

const checkInboxFolder = () => {
  console.log('Checking inbox...');

  if (!isConnected) {
    console.log('IMAP connection is not established. Skipping sync.');
    return;
  }

  // Open the inbox in "read-only" mode to ensure we don't modify any flags
  imap.openBox('Inbox', true, (err, box) => {  // Use 'true' for read-only mode
    if (err) {
      console.error('Error opening INBOX:', err);
      return;
    }
    console.log('Inbox opened in read-only mode:', box.name);

    // Search for only "UNSEEN" emails to fetch new emails
    imap.search(['UNSEEN'], async (err, results) => {
      if (err) {
        console.error('Error searching for emails:', err);
        return;
      }

      console.log('UNSEEN email IDs:', results);

      if (!results || results.length === 0) {
        console.log('No unseen emails found.');
        return;
      }

      console.log(`Found ${results.length} unseen email(s). Fetching emails...`);

      const fetch = imap.fetch(results, {
        bodies: ['HEADER.FIELDS (FROM SUBJECT MESSAGE-ID IN-REPLY-TO REFERENCES)', 'TEXT', ''],
        struct: true,
        markSeen: false,  // Explicitly avoid marking as seen during fetch
      });
      console.log('Mark Seen:', false);
      

      fetch.on('message', (msg, seqno) => {
        console.log(`Processing message #${seqno}`);
        let rawEmail = '';

        // Check the flags of the message as soon as the message is received
        msg.on('flags', (flags) => {
          console.log(`Flags for message #${seqno}:`, flags);
        });

        msg.on('body', (stream, parsed) => {
          // Handling email body part (either TEXT or HTML)
          stream.on('data', (chunk) => {
            rawEmail += chunk.toString();
          });

          stream.once('end', async () => {
            try {
              console.log('Parsing email...');
              const parsedEmail = await simpleParser(rawEmail);
              const senderEmail = parseSender(parsedEmail.from?.text || '');
              const messageId = parsedEmail.messageId || `<${uuidv4()}@yourdomain.com>`; // Generate fallback ID
              const inReplyTo = parsedEmail.inReplyTo || null;
              const references = parsedEmail.references || [];
              const subject = parsedEmail.subject || 'No Subject';
              let content = parsedEmail.text || parsedEmail.html || 'No Content';

              console.log(`Parsed message details:`, { senderEmail, content, messageId, inReplyTo, references, subject });

              // Clean up Word-specific and other unwanted tags in the content
              content = cleanWordMarkup(content);

              // Sanitize HTML content if it's HTML
              if (parsedEmail.html) {
                content = sanitizeEmailContent(content);
              }

              // Check for Spanish keywords in both subject and content
              const hasSpanishKeywords = spanishKeywords.some(keyword =>
                subject.toLowerCase().includes(keyword) || content.toLowerCase().includes(keyword)
              );

              if (!hasSpanishKeywords) {
                console.log('Email does not contain Spanish keywords in subject or content. Skipping ticket creation.');
                return; // Skip creating a ticket if no Spanish keywords are found
              }

              // Check if messageId is available before processing
              if (!messageId) {
                console.error('Message ID is missing. Skipping email...');
                return; // Skip the email if messageId is missing
              }

              // Check if the message ID has already been processed
              if (processedMessages.has(messageId)) {
                console.log(`Message ID ${messageId} already processed. Skipping.`);
                return;
              }

              processedMessages.add(messageId);

              const ticketData = {
                subject,
                sender: senderEmail,
                content,
                messageId,
                inReplyTo,
                references,
                status: 'pendiente',
                history: [],
                date: new Date(),
              };

              // Check if ticket already exists
              let ticket = await Ticket.findOne({
                $or: [
                  { messageId },
                  { messageId: inReplyTo },
                  { messageId: { $in: references } },
                ],
              });

              if (!ticket) {
                console.log('Creating a new ticket...');
                ticket = new Ticket(ticketData);  // Create new ticket using the ticket schema
              } else {
                console.log(`Updating existing ticket ID: ${ticket._id}`);

                // Avoid adding duplicate content to history
                const isAlreadyInHistory = ticket.history.some(
                  (historyItem) => historyItem.messageId === messageId
                );

                if (!isAlreadyInHistory) {
                  ticket.status = 'en proceso';  // Update ticket status to 'in process'
                  ticket.history.push({
                    content,
                    date: new Date(),
                    sender: senderEmail,
                    messageId,
                    inReplyTo,
                    references: [...ticket.references, ...references],
                  });
                  ticket.references = [...new Set([...ticket.references, ...references])];  // Update references
                }
              }

              // Save the ticket to the database
              await ticket.save();
              console.log(`Ticket saved successfully: ${ticket._id}`);

              // After processing, explicitly mark email as unseen
              imap.addFlags(seqno, '\\UNSEEN', (err) => {
                if (err) {
                  console.error('Error marking email as unseen:', err);
                } else {
                  console.log('Email marked as unseen successfully.');
                }
              });
            } catch (err) {
              console.error(`Error processing message #${seqno}:`, err);
            }
          });
        });

        msg.once('end', () => {
          console.log(`Finished processing message #${seqno}`);
        });
      });

      fetch.once('error', (err) => {
        console.error('Error during email fetching:', err);
      });

      fetch.once('end', () => {
        console.log('Finished fetching unseen emails.');
      });
    });
  });
};




// Check Trash for Deleted Emails
const checkTrashFolder = () => {
  imap.openBox('Trash', true, (err, box) => {
    if (err) {
      console.log('Error opening Trash folder:', err);
      return;
    }

    // Search for all emails in Trash folder (can filter as necessary)
    imap.search(['ALL'], async (err, results) => {
      if (err) {
        console.log('Error searching for emails in Trash:', err);
        return;
      }

      // If no emails are found in Trash, just return
      if (!results || results.length === 0) {
        console.log('No emails found in Trash.');
        return;
      }

      console.log(`Found ${results.length} email(s) in Trash. Processing...`);

      const fetch = imap.fetch(results, { bodies: '' });

      fetch.on('message', (msg, seqno) => {
        msg.on('body', async (stream) => {
          try {
            // Parse the email
            const parsed = await simpleParser(stream);
            const messageId = parsed.messageId;

            // If messageId exists and the email is found in MongoDB, delete it
            if (messageId) {
              const ticket = await Ticket.findOne({ messageId });
              if (ticket) {
                console.log(`Ticket with messageId ${messageId} found in MongoDB. Deleting ticket.`);
                await Ticket.deleteOne({ messageId });
                console.log(`Ticket with messageId ${messageId} deleted from MongoDB.`);
              }
            }
          } catch (err) {
            console.log('Error parsing email from Trash:', err);
          }
        });
      });

      fetch.once('end', () => {
        console.log('Finished fetching emails from Trash');
        imap.end(); // Close connection after fetching
      });
    });
  });
};

// Schedule cron jobs to check inbox and trash every 5 minutes
cron.schedule('* * * * *', () => {
  console.log('Corriendo el cron job para chequear Inbox y Trash folders...');
  if (!isConnected) {
    console.log('Not connected. Attempting to reconnect...');
    reconnectImap(); // Reconnect IMAP if disconnected
  } else {
    console.log('Checking inbox...');
    checkInboxFolder(); // Check for new emails in inbox
    checkTrashFolder(); // Check for emails in Trash
  }
});


registerImapEventHandlers();
imap.connect();


  //  Ticket.find({}).then(tickets => {
  //    console.log("Tickets in DB:", tickets);
  //  });


app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});