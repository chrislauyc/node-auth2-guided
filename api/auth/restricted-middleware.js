const jwt = require("jsonwebtoken")
const secret = require("../../config/secrets");
module.exports = (req, res, next) => {
  // add code here to verify users are logged in
  const token = req.headers.authorization;
  if(!token){
    return res.status(401).json({message:"token needed"});
  }
  jwt.verify(token,secret,(err,decoded)=>{
    if(err){
      return res.status(401).json({message:"token is bad: "+ err.message})
    }
    if(decoded){
      req.decodedToken = decoded;
      return next();
    }
  });
};
