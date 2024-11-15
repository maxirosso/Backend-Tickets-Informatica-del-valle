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
  subject: String,
  sender: String,
  content: String,
  date: { type: Date, default: Date.now },
  messageId: String,         // Unique ID of the original email message
  inReplyTo: String,         // ID of the message this one is in reply to
  references: [String],      // Array of messageIds in the conversation thread
  history: [
    {
      content: String,
      date: Date,
      sender: String,
      messageId: String,      // Unique ID for this specific history message
      inReplyTo: String,      // messageId of the previous message in the thread
      references: [String],   // Array of messageIds up to this point in the conversation
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
    let ticket;

    // Generate a new messageId for the ticket or reply (if not provided in the request body)
    const messageId = uuidv4();

    // Try to find a matching ticket based on inReplyTo or references
    if (inReplyTo) {
      // Find the ticket where messageId is either in the history or as the primary messageId
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
        content,
        date: new Date(),
        sender,
        messageId, // Ensure the messageId is unique and correctly assigned
        inReplyTo,  // This links the reply to the original message
        references: references ? references.split(' ') : [], // Maintain references
      });
      await ticket.save();
      return res.status(200).json({ message: 'Ticket updated successfully' });
    } else {
      // If no ticket found, create a new ticket (fallback)
      const newTicket = new Ticket({
        subject,
        sender,
        content,
        messageId, // The first message's unique ID
        inReplyTo,
        references: references ? references.split(' ') : [],
        history: [{ content, sender, date: new Date(), messageId, inReplyTo, references: references ? references.split(' ') : [] }],
      });
      await newTicket.save();
      return res.status(201).json({ message: 'Ticket saved successfully' });
    }
  } catch (err) {
    console.error('Error saving or updating ticket:', err);
    res.status(500).json({ message: 'Error saving or updating ticket' });
  }
});


// Route to reply to a ticket
app.post('/tickets/reply', auth, async (req, res) => {
  const { ticketId, replyMessage } = req.body;

  try {
    // Find the ticket by ID
    const ticket = await Ticket.findById(ticketId);
    if (!ticket) {
      console.log('Ticket not found');
      return res.status(404).json({ message: 'Ticket not found' });
    }

    // Add the reply to the ticket history
    ticket.history.push({
      content: replyMessage,
      date: new Date(),
      sender: req.user.username, // Ensure the sender is the logged-in user
    });

    // Save the updated ticket with the new reply in history
    const updatedTicket = await ticket.save();  // Save the ticket and return the updated ticket

    // Set up and send the email notification for the reply
    const transporter = nodemailer.createTransport({
      host: 'mr.fibercorp.com.ar',
      port: 465,
      secure: true,
      auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD,
      },
      tls: {
        rejectUnauthorized: false, // Disable SSL validation for self-signed certs
      },
    });

    const mailOptions = {
      from: process.env.EMAIL,
      to: ticket.sender,
      subject: `Re: ${ticket.subject}`,
      text: replyMessage,
    };

    await transporter.sendMail(mailOptions);

    // Send the updated ticket back to the frontend
    res.status(200).json(updatedTicket);  // Return the updated ticket instead of just a success message
  } catch (err) {
    console.error('Error sending reply:', err);
    res.status(500).json({ message: 'Error sending reply', error: err.message });
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

app.put('/tickets/:id/reply', auth, async (req, res) => {
  console.log("Reply endpoint hit");
  const { id } = req.params; // Ticket ID from URL
  const { replyMessage, inReplyTo, references, messageId } = req.body; // Extract necessary fields

  try {
    // Find the ticket by ID
    const ticket = await Ticket.findById(id);
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }

    // Log incoming data for debugging purposes
    console.log('Received reply:', { replyMessage, inReplyTo, references, messageId });

    // Ensure there's a history array in the ticket, initialize if necessary
    if (!ticket.history) {
      ticket.history = [];
    }

    // Construct the new reply object to be added to the ticket's history
    const newReply = {
      content: replyMessage,  // The content of the reply message
      date: new Date(),       // Date of the reply
      sender: req.user.username, // The sender's username (from the authenticated user)
      messageId,  // Unique ID for the message
      inReplyTo,  // Message ID this reply is responding to (null if it's the first message)
      references: references || [], // The message IDs to maintain the thread
    };

    // Add the new reply to the history
    ticket.history.push(newReply);

    // Check if the reply is a reply to a previous reply
    if (inReplyTo) {
      console.log("This is a reply to a previous reply:", {
        inReplyTo,
        originalReply: ticket.history.find(reply => reply.messageId === inReplyTo),
      });
    }

    // Log the updated ticket history before saving
    console.log("Updated ticket history:", ticket.history);

    // Save the updated ticket
    const updatedTicket = await ticket.save();

    // Log the updated ticket object
    console.log("Updated ticket after save:", updatedTicket);

    // Send email notification to the ticket sender
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
      to: ticket.sender,
      subject: `Re: ${ticket.subject}`,
      text: replyMessage, // The content of the reply message
    };

    await transporter.sendMail(mailOptions);

    // Return the updated ticket with the history included
    res.status(200).json(updatedTicket);
  } catch (err) {
    console.error('Error replying to ticket:', err);
    res.status(500).json({ message: 'Error replying to ticket', error: err.message });
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