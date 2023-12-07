const asyncHandler = (requestHandler) => {
    (req , res , next) => {
        Promise.resolve(requestHandler(req,res,next)).catch((err) => next(err))
    }
}

export {asyncHandler}

// const asyncHandler = () => {}
// const asyncHandler = (fun) => {() => {} }
//rempve curly braces
// const asyncHandler = (func) => async ()=>{}

// try catch method

// const asyncHandler = (fn) => async (req,res,next) => {
//     try{
//         await fn( req , res , next )
//     } catch(error){
//         res.status(err.code || 500).json({
//             success: false,
//             message:err.message
//         })
//     }
// }