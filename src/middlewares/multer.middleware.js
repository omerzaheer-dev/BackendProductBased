import multer from "multer";

//disk storage from multer github
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, "/BACKENDPRODUCTBASED/src/public/temp")           //path of file
    },
    filename: function (req, file, cb) {
    //   delete unique suffix
      cb(null, file.originalname)   //change with original name
    }
  })
  
  export const upload = multer({
     storage, 
   })