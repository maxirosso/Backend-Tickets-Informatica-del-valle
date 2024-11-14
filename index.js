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
  messageId: String,
  history: [
    {
      content: String,
      date: Date,
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

    // Only send the latest message if history exists
    const modifiedTickets = tickets.map(ticket => {
      if (ticket.history && ticket.history.length > 0) {
        return {
          ...ticket,
          content: ticket.history[ticket.history.length - 1].content, // Show last reply only
          historyCount: ticket.history.length, // Add history count to check in the frontend
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
  const { subject, sender, content, messageId } = req.body;

  const newTicket = new Ticket({ subject, sender, content, messageId });
  try {
    await newTicket.save();
    res.status(201).json({ message: 'Ticket saved successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error saving ticket' });
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
    });

    // Save the updated ticket with the new reply in history
    const updatedTicket = await ticket.save();  // Save the ticket and return the updated ticket

    // Set up and send the email
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
