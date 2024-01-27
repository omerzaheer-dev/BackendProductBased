//verify is li ku k login k wakt ref and access token gen kr ka cookie ma add kr dia ab check krna ha ref
//                                                 or access token true hain ya fake loggout krna sa phla
import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";
//not used res thats why _ used
const verifyJwt = asyncHandler(async (req,_,next) =>{
try {
    //optional chaining bcz mobile case data not comming from cookies user is giving costum headers
    const Token = req.cookies?.accessToken || req.header
    ("Authorization")?.replace("Bearer ","")
//data in headers come from authorization key and bearer space data value token accesstoken
//we dont need Bearer space in value because that why we are replacing it with  empty string we only need 
//                                                                               accesstoken after bearer
    if (!Token) {
        throw new ApiError(401," Unauthorized Request ")
    }
    //if have token then by using jwt we verify is it true or not and what is the info in token
    //to decode info from access token we have to give token to which be decode and also secret
    //of the bcz that can verify who have secret key while signing
    const decodedToken = jwt.verify(Token , process.env.ACCESS_TOKEN_SECRET)
//decode kra ga to jo data ho ga us ma sa id nikal lani ha
    const user = await User.findById(decodedToken?._id).select
    ("-password -refreshToken")
    if(!user){
        throw new ApiError(401,"Invalid Access Token")
    }
    //if user exist mean valid token in cookie 
    req.user = user;
    next()
} catch (error) {
    throw new ApiError(401,error?.message || "invalid access token")
}
})
export {
    verifyJwt,
}