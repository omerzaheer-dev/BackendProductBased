import dotenv from "dotenv";
dotenv.config({
    path: './.env'
})
import { app } from './app.js';
import connectDB from "./db/index.js";

connectDB()
.then(() => {
    app.listen(process.env.PORT , () =>{
        console.log(`server is running at port ${process.env.PORT}`);
    })
})
.catch((err) => {
    console.log("Mongo db connection failed ",err);
})