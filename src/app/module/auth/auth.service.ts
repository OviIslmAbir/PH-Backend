import bcrypt from "bcryptjs";
import type { JwtPayload, SignOptions } from "jsonwebtoken";
import { 
	AuthProvider,
	Role,
	UserStatus,
} from "../../../generated/prisma/enums";
import config from "../../config";
import { prisma } from "../../lib/prisma";
import { jwtUtils } from "../../utils/jwt";
import type {
	IForgotPasswordPayload,
	IGoogleLoginPayload,
	ILoginUserPayload,
	IRegisterPatientPayload,
	IRequestUser,
	IResetPasswordPayload,
} from "./auth.interface";
import type { TokenPayload } from "google-auth-library";
import { googleClient } from "../../lib/googleAuth";
import crypto from "crypto";
import { redisClient } from "../../lib/redis";
import { transporter } from "../../lib/nodemailer";
import ejs, { name } from "ejs";
import path from "path";

const registerPatient = async (payload: IRegisterPatientPayload) => {
	const { name, password, patient: patientData } = payload;
	const email = payload.email.trim().toLowerCase();

	const isUserExists = await prisma.user.findUnique({
		where: { email },
	});

	if (isUserExists) {
		throw new Error("User with this email already exists");
	}

	const hashedPassword = await bcrypt.hash(password, 8);

	const createdUser = await prisma.user.create({
		data: {
			name,
			email,
			password: hashedPassword,
			role: Role.PATIENT,
			status: UserStatus.ACTIVE,
			emailVerified: false,
			patient: {
				create: { name, email, contactNumber: patientData.contactNumber || "" },
			},
		},
		omit: { password: true },
		include: { patient: true },
	});

	const { patient, ...user } = createdUser;
	const jwtPayload = {
		userId: user.id,
		name: user.name,
		email: user.email,
		role: user.role,
	};

	const accessToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_access_secret,
		config.jwt_access_expires_in as SignOptions,
	);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		user,
		patient,
		accessToken,
		refreshToken,
	};
};

const loginUser = async (payload: ILoginUserPayload) => {
	const { password } = payload;
	const email = payload.email.trim().toLowerCase();

	const user = await prisma.user.findUnique({
		where: { email },
	});

	if (!user) {
		throw new Error("User not found");
	}

	if (user.status === UserStatus.BLOCKED) {
		throw new Error("User is blocked");
	}

	if (user.isDeleted || user.status === UserStatus.DELETED) {
		throw new Error("User is deleted");
	}
	if (user.password === null && user.googleId !== null) {
		throw new Error(
			"User Already has account with Google. Please login with Google",
		);
	}

	const isPasswordMatched = await bcrypt.compare(
		password,
		user.password as string,
	);

	if (!isPasswordMatched) {
		throw new Error("Invalid credentials");
	}

	const jwtPayload = {
		userId: user.id,
		name: user.name,
		email: user.email,
		role: user.role,
	};

	const accessToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_access_secret,
		config.jwt_access_expires_in as SignOptions,
	);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		accessToken,
		refreshToken,
	};
};

const getMe = async (user: IRequestUser) => {
	const isUserExists = await prisma.user.findUnique({
		where: {
			id: user.userId,
		},
		include: {
			patient: true,
		},
		omit: {
			password: true,
		},
	});

	if (!isUserExists) {
		throw new Error("User not found");
	}

	return isUserExists;
};

const refreshToken = async (token: string) => {
	const verifiedRefreshToken = jwtUtils.verifyToken(
		token,
		config.jwt_refresh_secret,
	);

	if (!verifiedRefreshToken.success || !verifiedRefreshToken.data) {
		throw new Error(
			config.node_env === "development"
				? verifiedRefreshToken.error
				: "Invalid refresh token",
		);
	}

	const data = verifiedRefreshToken.data as JwtPayload;

	const user = await prisma.user.findUnique({
		where: { id: data.userId },
	});

	if (!user || user.isDeleted || user.status !== UserStatus.ACTIVE) {
		throw new Error("User is inactive or not found");
	}

	const jwtPayload = {
		userId: user.id,
		name: user.name,
		email: user.email,
		role: user.role,
	};

	const accessToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_access_secret,
		config.jwt_access_expires_in as SignOptions,
	);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		accessToken,
		refreshToken,
	};
};
const googleLogin = async (payload: IGoogleLoginPayload) => {
	let googleIdTokenPayload: TokenPayload | null | undefined = null;
	try {
		const ticket = await googleClient.verifyIdToken({
			idToken: payload.idToken,
			audience: config.google_client_id,
		});
		googleIdTokenPayload = ticket.getPayload();
	} catch (error) {
		console.error("Error verifying Google ID token:", error);

		throw new Error("Invalid or Expired Google ID token");
	}
	if (!googleIdTokenPayload) {
		throw new Error("Invalid or Expired Google ID token");
	}
	if (!googleIdTokenPayload.email) {
		throw new Error("Email not found in Google ID token payload");
	}
	if (!googleIdTokenPayload.name) {
		throw new Error("Name not found in Google ID token payload");
	}

	const ifPatientExistsWithGoogleAuth = await prisma.user.findUnique({
		where: {
			email: googleIdTokenPayload.email,
			role: Role.PATIENT,
			googleId: googleIdTokenPayload.sub,
		},
	});
	let user = ifPatientExistsWithGoogleAuth;
	if (!ifPatientExistsWithGoogleAuth) {
		const ifPatientExistsWithCredentialsAuth = await prisma.user.findUnique({
			where: {
				email: googleIdTokenPayload.email,
				role: Role.PATIENT,
				authProvider: AuthProvider.CREDENTIALS,
			},
		});
		if (ifPatientExistsWithCredentialsAuth) {
			if (!ifPatientExistsWithCredentialsAuth.emailVerified) {
				throw new Error(
					"Email is not verified. Please verify your email before logging in with Google.",
				);
			}
			if (ifPatientExistsWithCredentialsAuth.status === UserStatus.BLOCKED) {
				throw new Error("User is blocked");
			}
			if (
				ifPatientExistsWithCredentialsAuth.isDeleted ||
				ifPatientExistsWithCredentialsAuth.status === UserStatus.DELETED
			) {
				throw new Error("User is deleted");
			}
			user = await prisma.user.update({
				where: {
					id: ifPatientExistsWithCredentialsAuth.id,
				},
				data: {
					googleId: googleIdTokenPayload.sub,
				},
			});
		} else {
			user = await prisma.user.create({
				data: {
					name: googleIdTokenPayload.name,
					email: googleIdTokenPayload.email,
					role: Role.PATIENT,
					googleId: googleIdTokenPayload.sub,
					emailVerified: true,
					authProvider: AuthProvider.GOOGLE,
					patient: {
						create: {
							name: googleIdTokenPayload.name,
							email: googleIdTokenPayload.email,
						},
					},
				},
			});
		}
	}
	if (!user) {
		throw new Error("User Not Found or Created");
	}
	if (user.status === UserStatus.BLOCKED) {
		throw new Error("User is blocked");
	}
	if (user.isDeleted || user.status === UserStatus.DELETED) {
		throw new Error("User is deleted");
	}
	const jwtPayload = {
		userId: user.id,
		name: user.name,
		email: user.email,
		role: user.role,
	};

	const accessToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_access_secret,
		config.jwt_access_expires_in as SignOptions,
	);

	const refreshToken = jwtUtils.createToken(
		jwtPayload,
		config.jwt_refresh_secret,
		config.jwt_refresh_expires_in as SignOptions,
	);

	return {
		accessToken,
		refreshToken,
	};
};
const forgotPassword = async (payload: IForgotPasswordPayload) => {
   const { email } = payload;
   const isUserExists = await prisma.user.findUnique({
	  where: { email },
   });
   if (!isUserExists) {
	  throw new Error("User not found");
   }
   if(isUserExists.status === "BLOCKED") {
	  throw new Error("User is blocked");
   }
   if(isUserExists.isDeleted || isUserExists.status === "DELETED") {
	  throw new Error("User is deleted");
   }
   if(isUserExists.googleId || isUserExists.authProvider !== "CREDENTIALS") {
	  throw new Error("User has registered with Google. Please login with Google");
   }
   if(!isUserExists.emailVerified){
	 throw new Error("User Not Verified")
   }
   const otp = crypto.randomInt(100000, 999999).toString();

   const key = `forgot-password-otp:${isUserExists.email}`

   await redisClient.set(key,otp,{
	 expiration: {
		type: "EX",
		value: 5 * 60
	 }
   })

    const templatePath = path.join(process.cwd(), "src/app/templates/forgot-password.ejs")

    const html = await ejs.renderFile(templatePath, {
		name: isUserExists.name,
		otp,
		expirationMinutes: (5 * 60) / 60
	})


   await transporter.sendMail({
	 from: config.email_sender,
	 to : isUserExists.email,
	 subject: "Forgot Password",
	 html
   })
}
const resetPassword = async (payload: IResetPasswordPayload) => {
   const { email,otp,newPassword } = payload;
   const isUserExists = await prisma.user.findUnique({
	  where: { email },
   });
   if (!isUserExists) {
	  throw new Error("User not found");
   }
   if(isUserExists.status === "BLOCKED") {
	  throw new Error("User is blocked");
   }
   if(isUserExists.isDeleted || isUserExists.status === "DELETED") {
	  throw new Error("User is deleted");
   }
   if(isUserExists.googleId || isUserExists.authProvider !== "CREDENTIALS") {
	  throw new Error("User has registered with Google. Please login with Google");
   }
   if(!isUserExists.emailVerified){
	 throw new Error("User Not Verified")
   }
    const key = `forgot-password-otp:${isUserExists.email}`

   const redisOtp = await redisClient.get(key)
   if(!redisOtp){
	throw new Error("Invalid OTP")
   }
   if(redisOtp !== otp){
    throw new Error("OTP dose not match")
   }

   const hashedNewPassword =  await bcrypt.hash(newPassword, Number( config.bcrypt_salt_rounds));

   await prisma.user.update({
		where : {
			email: isUserExists.email
		},
		data:{
			password: hashedNewPassword
		}
   })

    const templatePath = path.join(process.cwd(), "src/app/templates/reset-password.ejs")

    const html = await ejs.renderFile(templatePath, {
		name: isUserExists.name,
	})
    await transporter.sendMail({
	 from: config.email_sender,
	 to : isUserExists.email,
	 subject: "Password Changed",
	 html
   })

   await redisClient.del([key])

}
export const AuthService = {
	registerPatient,
	loginUser,
	getMe,
	refreshToken,
	googleLogin,
	forgotPassword,
	resetPassword,
};
