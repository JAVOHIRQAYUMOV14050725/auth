import { Router } from "express";
import { authRouter } from "./auth.route";

let router:Router = Router()

router.use("/auth",authRouter)

export {router}