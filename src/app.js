const express = require("express");
const stream = require("stream");
const dotenv = require("dotenv");
const cloudinary = require("cloudinary").v2;
const app = express();
const PORT  = process.env.PORT || 3000
const hbs = require("hbs");
const bodyParser = require("body-parser");
const multer = require('multer');
const path = require("path");
const upload = multer({ storage: multer.memoryStorage() });
const { GridFSBucket } = require("mongodb");
const passport= require("passport");
const session = require('express-session');
const moment = require('moment');
const fileupload = require("express-fileupload");

app.use(fileupload({ useTempFiles: true }));
const hbsHelpers = {
    timeago: function(date) {
    return moment(date).fromNow();
  }
};

cloudinary.config({
  cloud_name: "dar4ws6v6",
  api_key: "131471632671278",
  api_secret: "d0UW2ogmMnEEMcNVcDpzG33HKkY",
});

// Register helpers with hbs
hbs.registerHelper(hbsHelpers);

require('dotenv').config()
dotenv.config();



app.use(session({
  secret: "44216c18086ba8168d42e1f872a2eababbdd9c4e537cd153f8f38bfe836314ba",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

function isLoggedIn(req,res , next) {
  req.user ? next() : res.status(401).send("either your session has been expired or you are not authorized so please login again");
};

//'mongodb://127.0.0.1:27017/mernproject',
const MONGO_URL =  'mongodb+srv://saurabhkumar:rVKACHYbuzYy7VMs@cluster0.n4zogin.mongodb.net/newnotesdatabase?retryWrites=true&w=majority'
app.use(bodyParser.json());
//const uri = process.env.MONGO_URL;
const mongoose = require("mongoose");
mongoose.set('strictQuery',false);
const db = mongoose.connection;
mongoose.connect(MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function() {
    //we are connected
    console.log("we are connected...");
});

app.use(express.static(path.join(__dirname,"../templates/views/public")));
app.use("/uploads", express.static(path.join(__dirname, "public/uploads")));
app.use(express.json());
app.use(express.urlencoded({extended:false}));

const template_path = path.join(__dirname, "../templates/views");
const partial_path = path.join(__dirname, "../templates/partials");

app.set("views", template_path);
app.set("view engine", "hbs");
hbs.registerPartials(partial_path);

app.get("/", (req, res) => {
    res.render("index");
});
app.get("/home", (req, res) => {
   res.render("index");
});
app.get("/login", (req, res) => {
  // res.send("hello from saurabh")
   res.render("login");
});
app.get("/upload", isLoggedIn,(req, res) => {
   // res.send("hello from saurabh")
    res.render("upload", {user: req.user,});
});
app.get("/register", (req,res) => {
   res.render("register");
});
app.get("/searchnotes", isLoggedIn, (req, res) =>{
  res.render("searchpdf",  {
    user: req.user,});
});
app.get("/services", (req,res) =>{
  res.render("aboutus");
})

//now we need to create a collection

const uploadSchema = new mongoose.Schema({
  filename: String,
  uploader_name: String,
  subject: String,
  fileId: String,
  cloudinary_url: String, 
  uploadDate: { type: Date, default: Date.now }
});

const Upload =new mongoose.model('Upload', uploadSchema);

//new schema for google
const employeeSchemaa = new mongoose.Schema({
  name : {
      type:String,
      required:true
  },
  email: {
      type:String,
      required:true
     
  },
  avatar: {
    type: String,
    required: true
  },
  numUploads: {
    type: Number,
    default: 0
  },
  uploads: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Upload'
  }],
  filePath: {
    type: String
  }
 
})
//now we need to create a collection
const Newregister = new mongoose.model("Googleregister", employeeSchemaa);

//schena for post
const UserSchema = new mongoose.Schema({
  posttext: {
    type: String,
    required: true
  },
  postimage: {
    type:String,
    required: false

  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Googleregister",
    required: true
  },
  comments: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "Comment",
    required: false
  }],
  likes: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Googleregister",
      required: true
    }
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
 
});

const UserPost = new mongoose.model("UserPost", UserSchema);

//comment Schema
const CommentSchema = new mongoose.Schema({
  comment: {
    type: String,
    required: true
   },
   user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Googleregister",
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
   
});

const Comment = new mongoose.model("Comment", CommentSchema);

app.post('/upload',isLoggedIn, async (req, res) => {
  if (!req.user) {
    res.redirect('/login');
    return;
  }

  if (!req.files || !req.files.pdf) {
    res.status(400).send('No PDF file uploaded');
    return;
  }

  const pdfFile = req.files.pdf;

  const metadata = {
    uploader_name: req.body.uploader,
    subject: req.body.subject,
  };

  try {
    const result = await cloudinary.uploader.upload(pdfFile.tempFilePath, {
      resource_type: 'raw',
    });

    const newUpload = new Upload({
      filename: pdfFile.name,
      uploader_name: metadata.uploader_name,
      subject: metadata.subject,
      fileId: result.public_id,
      cloudinary_url: result.secure_url,
    });

    newUpload.save(async (err, upload) => {
      if (err) {
        console.error('Error saving upload document:', err);
        res.status(500).send('Error saving upload document');
        return;
      }

      const userId = req.user._id;

      try {
        const user = await Newregister.findById(userId);

        if (!user) {
          res.status(500).send('Error finding user');
          return;
        }

        user.uploads.push(newUpload._id);
        user.numUploads++;
        await user.save();
        res.status(201).redirect('/uploaded');
      } catch (err) {
        console.error('Error updating user document count:', err);
        res.status(500).send('Error updating user document count');
      }
    });
  } catch (error) {
    console.error('Error uploading to Cloudinary:', error);
    res.status(500).send('Error uploading PDF file');
  }
});

 app.get("/uploaded", isLoggedIn,(req, res) =>{
  if (!req.user) {
    // Handle the case where req.user is undefined
    res.redirect('/login');
    return;
  }
  const success = "your document uploaded successfully";
   res.render("upload", {user: req.user,success});
 });


 //getting pdf
 
  app.get("/search",isLoggedIn, function (req, res) {
    if (!req.user) {
      // Handle the case where req.user is undefined
      res.redirect('/login');
      return;
    }
    const query = req.query.pdf;
    if (!query) {
      res.status(400).send("Please enter a search term");
      return;
    }
    const searchStream = bucket.find({
      $or: [
        { filename: { $regex: new RegExp(query, "i") } },
        { subject: { $regex: new RegExp(query, "i") } },
        { "metadata.subject": { $regex: new RegExp(query, "i") } }
      ]
    }).stream();
   
    const results = [];
    searchStream.on("data", function (file) {
      //const downloadLink = `/download/${file._id}`;
      const downloadLink = `http://uornotes.cyclic.app/download/${file._id}`;

      results.push({
        filename: file.filename,
        uploader_name: file.metadata.uploader_name,
        subject: file.metadata.subject,
        downloadLink: downloadLink,
      });
    });
    searchStream.on("end", function () {
      if (results.length > 0) {
        res.render("searchpdf", { results, displayResults: "block", user: req.user });
      } else {
        res.render("searchpdf", {  displayResultsx: "block" , user: req.user});
      }
    });
  });
  
 app.get('/download/:id',isLoggedIn, async (req, res) => {
    const fileId = req.params.id;
  
    try {
      const upload = await Upload.findOne({ fileId: fileId });
  
      if (!upload) {
        res.status(404).send('File not found');
        return;
      }
      res.setHeader('Content-Disposition', `attachment; filename="${upload.filename}"`);
      res.redirect(upload.cloudinary_url); // Redirect to the Cloudinary URL
    } catch (err) {
      console.error('Error fetching upload document:', err);
      res.status(500).send('Error fetching upload document');
    }
  });


//postsextion
app.post("/post",isLoggedIn, async (req, res) =>{
  try{
  
    //const postimage = req.file ? req.file.path : '';
    const file = req.files.postimage;

    const result = await cloudinary.uploader.upload(file.tempFilePath, {
      folder: "uploads",
    });

    const postimage = result.secure_url;
    
    const posttext = req.body.posttext;
    const user = req.user._id;
    const comment = req.user._id;

    const Userpost = new UserPost({
      posttext,
      postimage: postimage,
      user,
      comment
    });
    await Userpost.save();
    console.log("post saved successfully");
    //res.send("post saved");
    res.redirect("/protected");

  } catch(err){
    res.send("internal server error")
    console.log(err);
  }
});

//delete
app.post("/deletepost/:postId",  isLoggedIn, async (req, res) => {
  try {
    const postId = req.params.postId;
    const post = await UserPost.findById(postId);
  
    if (!post) {
      return res.status(404).send('Post not found');
    }
    
    await UserPost.findByIdAndDelete(postId);

    console.log("Post deleted successfully");
    res.status(200).json({ message: "Post deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});



//commentpost
app.post("/comment", async (req, res) =>{
  try{
    const comment = req.body.comment;
    const user = req.user._id;
    const postid = req.body.postid;
    const commentNew = new Comment({
      comment,
      user
    });
    await commentNew.save();
    const userPost = await UserPost.findById(postid);
    userPost.comments.push(commentNew._id);
    await userPost.save();
    console.log("comment addedd");
    //res.redirect("/protected");
    const userr = await Newregister.findById(req.user._id); // Get the user who posted the comment
    const response = {
      postid: postid,
      name: userr.name,
      avatar: userr.avatar,
      comment: comment
    };
    res.json(response); 
  } catch(err){
    console.log(err);
  }
});

//likefunction
app.post('/like-post/:id', async function(req, res) {
  const postId = req.params.id;
  
  try {
    const post = await UserPost.findById(postId);
  
    if (!post) {
      return res.status(404).send('Post not found');
    }
  
    const userLikedPost = post.likes.some((like) => {
      return like.user.toString() === req.user._id.toString();
    });
  
    if (userLikedPost) {
      post.likes = post.likes.filter((like) => {
        return like.user.toString() !== req.user._id.toString();
      });
    } else {
      post.likes.push({
        user: req.user._id
      });
    }
  
    await post.save();
    const likesCount = post.likes.length;
    console.log("like addedd");
    res.json({ likesCount });
  
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal server error');
  }
});


//google authentication
//var GoogleStrategy = require("passport-google-oauth20").OAuth2Strategy;;
//const {Strategy: GoogleStrategy} = require('passport-google-oauth20');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const clientSecreT = require("../config/googledata").clientSecret;
const clientId = require("../config/googledata").clientID;

passport.use(new GoogleStrategy({
  clientID: clientId,
  clientSecret: clientSecreT,
  callbackURL: 'https://uornotes.cyclic.app/google/callback',
}, (accessToken, refreshToken, profile, done) => {
  Newregister.findOne({  email: profile.emails[0].value }).then(existingUser => {
    if (existingUser) {
      // User already exists, return user
      done(null, existingUser);
    } else {
      // User does not exist, create user and return
      new Newregister({
        googleId: profile.id,
        name: profile.displayName,
        email: profile.emails[0].value,
        avatar: profile.photos[0].value,
      }).save().then(newUser => {
        done(null, newUser);
      });
    }
  }).catch(err => {
    done(err, null);
  });
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});


// Deserialize user
passport.deserializeUser((id, done) => {
  Newregister.findById(id).then(user => {
    done(null, user);
  }).catch(err => {
    done(err, null);
  });
});

app.get("/google", passport.authenticate('google', { scope : ['profile', 'email',]}));

app.get("/google/callback", passport.authenticate('google', { 
  successRedirect: '/protected',
 failureRedirect: '/'}));

 app.get("/protected", isLoggedIn, async (req, res) =>{
  try {

    if (!req.user) {
      // Handle the case where req.user is undefined
      res.redirect('/login');
      return;
    }
    const user = req.session.user
    const userPosts = await UserPost.find({})
    .populate({ path: 'user', select: 'name avatar' })
    .populate({ path: 'comments', select: 'comment user', populate: { path: 'user', select: 'name avatar' }, options: { sort: { createdAt: -1 }, strictPopulate: false } })
    .sort({ createdAt: -1 })
    //.sort({ date: 'desc' }).lean();
    

    //userPosts.reverse();
    res.render('home', {  userPosts, user, user: req.user, hbsHelpers }); 
   
  }
  
   catch (err) {
    res.send('internal server error');
    console.log(err);
  }
 
 });

 //logout
 app.get('/logout', isLoggedIn,function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});


//profilesection
app.get("/profile", isLoggedIn, async (req, res) => {
  try {
    if (!req.user) {
      res.redirect('/login');
      return;
    };
    const userId = req.user._id;
    const user = await Newregister.findById(userId).populate('uploads').exec();

    const uploads = user.uploads.map((upload) => {
      const downloadLink = `/download/${upload.fileId}`;
      return {
        uploader_name: upload.uploader_name,
        filename: upload.filename,
        subject: upload.subject,
        downloadLink: downloadLink
      }
     
    });
    console.log(uploads);

    const userPosts = await UserPost.find({ user: userId }).populate("user")
    .populate({ path: 'user', select: 'name avatar' })
    .populate({ path: 'comments', select: 'comment user', populate: { path: 'user', select: 'name avatar' }, options: { sort: { createdAt: -1 }, strictPopulate: false } })
    .sort({ createdAt: -1 }); 

    res.render("profile", { uploads, userPosts, user: req.user, hbsHelpers });
  } catch (err) {
    res.status(500).send("Internal server error");
    console.log(err);
  }
});


//crypto generation for express-session
const crypto = require('crypto');

const secretKey = crypto.randomBytes(32).toString('hex');
console.log(secretKey);



//app listening
app.listen(PORT, () => {
   console.log(`server is running at port no ${PORT}`);
});
