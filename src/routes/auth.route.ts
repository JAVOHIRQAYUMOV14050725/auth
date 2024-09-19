import { AuthController } from '@controllers';
import { authenticateToken } from '@middlewares';
import { Router } from 'express';

const authRouter = Router();

authRouter.post('/register', AuthController.register);
authRouter.post('/verify', AuthController.verify);
authRouter.post('/login', AuthController.login);
authRouter.post('/forgotPassword', AuthController.forgotPassword);
authRouter.patch('/changePassword',authenticateToken, AuthController.changePassword);
authRouter.post('/resetPassword',authenticateToken, AuthController.resetPassword);
authRouter.get('/getProfile',authenticateToken, AuthController.getProfile);


export  {authRouter};
