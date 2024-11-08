const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors());

// MongoDB setup (same as your current configuration)
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => console.log("MongoDB connection error:", err));

// Ticket model
const ticketSchema = new mongoose.Schema({
  subject: String,
  sender: String,
  content: String,
  date: { type: Date, default: Date.now }
});

const Ticket = mongoose.model('Ticket', ticketSchema);

// Route to fetch tickets (existing)
app.get('/tickets', async (req, res) => {
  try {
    const tickets = await Ticket.find();
    res.json(tickets);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching tickets' });
  }
});

// Route to save a ticket (you could call this when you want to insert tickets into MongoDB)
app.post('/tickets', async (req, res) => {
  const { subject, sender, content } = req.body;

  const newTicket = new Ticket({ subject, sender, content });
  try {
    await newTicket.save();
    res.status(201).json({ message: 'Ticket saved successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error saving ticket' });
  }
});

// Route to reply to a ticket
app.post('/tickets/reply', async (req, res) => {
  const { ticketId, replyMessage } = req.body;

  try {
    // Fetch the ticket to get the sender's email
    const ticket = await Ticket.findById(ticketId);
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }

    // Configure nodemailer transport with your custom SMTP server
    const transporter = nodemailer.createTransport({
      host: 'mr.fibercorp.com.ar', // SMTP server
      port: 465,  // SMTP port
      secure: true, // Use SSL/TLS
      auth: {
        user: process.env.EMAIL, // Your email (informática@delvalle.edu.ar)
        pass: process.env.PASSWORD, // Your email password (or app-specific password)
      }
    });

    // Send the reply email
    const mailOptions = {
      from: process.env.EMAIL,  // From your email
      to: ticket.sender,        // Recipient email (sender of the ticket)
      subject: `Re: ${ticket.subject}`,
      text: replyMessage,       // Reply message content
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Reply sent successfully' });
  } catch (err) {
    console.error('Error sending reply:', err); // Log the error
    res.status(500).json({ message: 'Error sending reply', error: err.message });
  }
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
