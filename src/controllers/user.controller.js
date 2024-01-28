import { ApiError } from "../utils/ApiError.js"
import { asyncHandler } from "../utils/asyncHandler.js";
import { User } from "../models/user.model.js"
import { uploadOnCloudinary } from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import { Jwt } from "jsonwebtoken"; 

//we are getting iser id from login controller user when pass is checked
const generateRefreshAndAccessTokens = async(userId) => {
    try {
        const user = await User.findById(userId)
        const accesstoken = user.generateAcessToken()
        const refreshToken = user.generateRefreshToken()
        //access token ko hum user to da data hain but ref token ko data ma save krta hain taka password na puchna pra user sa baar baar
        //ref token to db ma kasa add krain
        user.refreshToken = refreshToken
        await user.save({validateBeforeSave: false})
        //mongose model kickin to validation kha gi pass is req flana dhimkana is required thats why we use validateBeforeSave: false

        return {accesstoken , refreshToken}
    } catch (error) {
        throw new ApiError(500,"Something went wrong while generating ref and access tokens")
    }
}

const registerUser = asyncHandler( async (req , res) => {
    //steps to register 
    // get user details from frontend 
    // validation check empty field email syntax
    // check if user already exists username , email
    // check for images and avatar
    // opload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for response and user creation 
    // return response

    const { username , email , fullname , password } = req.body
    //console.log("email: ",email);

    if (
        [fullname,email,username,password].some((field) =>
        field?.trim() === "" )
    ) {
        throw new ApiError(400, "All fields are required")
    }

    const existedUser = await User.findOne({
        $or: [{ username } , { email }]
    })

    //just for testing what req files hold we are console loging
    //console.log(req.files);

    if (existedUser) {
        throw new ApiError(409, "User with email or username already exists")
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    //const coverImageLocalPath = req.files?.coverImage[0]?.path;

    //checking coverImage
    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0]?.path;
    }

    if (!avatarLocalPath) {
        throw new ApiError(400,"AvatarLocal is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if (!avatar) {
        throw new ApiError(400,"Avatar file is required")
    }

    const user = await User.create({
        fullname,
        avatar:  avatar?.url ,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase(),
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    );

    if(!createdUser) {
        throw new ApiError(500,"Somthing went wrong while registering user")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser , "User registered successfully")
    )

} )


const loginUser = asyncHandler( async (req , res) => {
    //take username / email or password
    //username or email
    //find the user
    //password check
    //access and refresh token generate and snd to user
    //snd to cookies secure cookies

    const {email , username , password} = req.body;
    if (!( username && email )) {
        throw new ApiError(400,"username and email is required")
    }

    //if we need only one of username or email than we can use
    // this code otherwise if we require both than upper
    // if (!( username || email )) {
    //     throw new ApiError(400,"username or email is required")
    // }
    //kuch be bhaja ho sakta ha isi lia or op in mongo db
    const user = await User.findOne({
        $or: [{ username } , { email }]
    })


    if (!user) {
        throw new ApiError(404," User doesnot exist ")
    }

    //to check pass we have method is pass correct requiring from methods
    const ValidatePassword = await user.isPasswordValid(password);
    if (!ValidatePassword) {
        throw new ApiError(401," Invalid User Cradentials ")
    }

    //genrating ref access tokens
    //await bcz db operations are using in the method below
    const {refreshToken , accesstoken} = await generateRefreshAndAccessTokens(user._id)
    //snd to cookies
    //what we info snd to user
    //not to snd pass
    //uper wala user ka pass ref token ni ha ku ka method to bad ma call hua ha isi lia hum dobara sa find
    //                          kra ga user ko taka reftoken aa jai updated but us to remove kr k bhaja ga
    const loggedInUser = await User.findById(user._id).
    select("-password -refreshToken")

    //snd cookies so we have to create options object
    //object ki zaroorat is lia ha by default any one can modify cookies but the object of options httponly
    //                                                  and secure makes it modifyable only from the server
    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken",accesstoken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(
        new ApiResponse(
            200,
            {
                user: loggedInUser, accesstoken, refreshToken
            },
            "User logged in successfully"
        )
    )

//jb cookie ma save kr dia alag sa res bhajna ka faida ya ha ka browser save krta ha cookie ho sakta user
//                                                         local storage ya mobile app ma save kr raha ho 
} )

const loogoutUser = asyncHandler( async (req , res) => {
    //clear cookies
    //reftoken to bi to clear krna ha tabi to loogout ho ga wo
    //by middleware req.user._id
    const updatedUser = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )
    const options = {
        httpOnly: true,
        secure: true
    }
    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(
        new ApiResponse(200,{},"User LogedOut Successfully")
    )
})

const refreshAccessToken = asyncHandler( async ( req , res ) => {
    //access token is short lived user have to login again to refresh access token but 
    //if access token invalidates or times up 401 req frontend person dont say to login he 
    //can hit endpoint if 401 req refresh access token you send ref token in req we match that
    //token with database token
    
    //1. send ref token
    const incommingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if( !incommingRefreshToken ){
        throw new ApiError(401,"unauthorized request")
    }

    //2.verify 
    const decodedToken = jwt.verify(
        incommingRefreshToken,
        process.env.REFRESH_TOKEN_SECRET
    )

    //
    const user = await User.findById(decodedToken?._id)
    if( !user ){
        throw new ApiError(401,"invalid refresh token")
    }
    //now  mach token from user nd data base 
    if ( incommingRefreshToken !== user?.refreshToken ) {
        throw new ApiError(401,"Refresh token is expired or used")
    }

    const options = {
        httpOnly : true,
        secure : true
    }
    const {accesstoken,newRefreshToken} = await generateRefreshAndAccessTokens(user._id)
    return res.
    status(200).
    cookie("accessToken",accesstoken,options).
    cookie("refreshToken",newRefreshToken,options).
    json(
        new ApiResponse(
            200,
            {"acceToken": accesstoken,"refreshToken": newRefreshToken},
            "Access Token Refreshed"
        )
    )
} )

const changeCurrentPassword = asyncHandler(async (req,res) => {
    const {oldPassword,newPassword,confirmPassword} = req.body
    if( newPassword !== confirmPassword ){
        throw new ApiError(401,"new password and confirm password does not match")
    }
    const user = await User.findById(req.user?._id);
    const validatePassword = await user.isPasswordValid(oldPassword);
    if(!validatePassword){
        throw new ApiError(400,"invalid oldPassword")
    }
    user.password = newPassword;
    await user.save({validateBeforeSave:false})

    return res.
    status(200).
    json(new ApiResponse(200,{},"password saved successfully"))
})

const getCurrentUser = asyncHandler(async(req,res) => {
    return res.
    status(200).
    json(new ApiResponse(200,req.user,"current user fetched successfully "))
})

const updateAccountDetails = asyncHandler(async(req,res) => {
    const {fullname,email} = req.body;

    if(!fullname || !email) {
        throw new ApiError(400,"fullname and email is required ");
    }
    const user = await User.findByIdAndUpdate(req.user?._id,{
        $set: {
            fullname,
            email
        }
    },{
        new:true
    }).select("-password")

    return res.
    status(200).
    json(new ApiResponse(200,user,"Account details updated successfully"))
})

const updateAvatar = asyncHandler(async (req,res) =>{
    //phla in register controler we have taken req.file but now 
    //we are taking file bcz previously we were updating multiple files
    const avatarLocalPath = req.file?.path
    if(!avatarLocalPath) {
        throw new ApiError(400,"Avatar file is missing ");
    }
    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar.url){
        throw new ApiError(400,"Error while uploading on avatar");
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set : {
                avatar:avatar.url
            }
        },{
            new:true
        }
    ).select("-password")
    return res.
    status(200).
    json(200,user,"avatar updated successfully")
})
const updateUserCoverImage = asyncHandler(async (req,res) =>{
    //phla in register controler we have taken req.file but now 
    //we are taking file bcz previously we were updating multiple files
    const coverImageLocalPath = req.file?.path
    if(!coverImageLocalPath) {
        throw new ApiError(400,"Cover image file is missing ");
    }
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!coverImage.url){
        throw new ApiError(400,"Error while uploading coverImage");
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set : {
                coverImage:coverImage.url
            }
        },{
            new:true
        }
    ).select("-password")
    return res.
    status(200).
    json(200,user,"coverImage updated successfully")
})
export {
    registerUser,
    loginUser,
    loogoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAvatar,
    updateUserCoverImage,
    updateAccountDetails,

}