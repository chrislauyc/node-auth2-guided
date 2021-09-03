module.exports = {
    checkRole: (role)=>(req,res,next)=>{
        if(role==="admin"){
            if(req.decodedToken.role === role){
                return next();
            }
            else{
                res.status(403).json({message:"you need to be an admin"})
            }
        }
    }
}