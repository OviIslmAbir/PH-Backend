import z from "zod";

const PatientRegistrationZodSchema = z.object({
	name: z
		.string()
		.min(3, { message: "Name must be at least 3 characters long" })
		.max(10, { message: "Name cannot exceed 10 characters" }),

	email: z.email({ message: "Please provide a valid email address" }),

	password: z
		.string()
		.min(8, { message: "Password must be at least 8 characters long" })
		.max(32, { message: "Password cannot exceed 32 characters" })
		.regex(/[A-Z]/, {
			message: "Password must contain at least one uppercase letter",
		})
		.regex(/[a-z]/, {
			message: "Password must contain at least one lowercase letter",
		})
		.regex(/[0-9]/, {
			message: "Password must contain at least one number",
		})
		.regex(/[^A-Za-z0-9]/, {
			message: "Password must contain at least one special character",
		}),

	patient: z
		.object({
			contactNumber: z
				.string()
				.min(11, {
					message: "Contact number must be at least 11 characters long",
				})
				.max(15, {
					message: "Contact number cannot exceed 15 characters",
				})
				.regex(/^[0-9]+$/, {
					message: "Contact number must contain only numbers",
				})
				.optional(),
		})
		.optional(),
});

const PatientLoginZodSchema = z.object({
	email: z.email({ message: "Please provide a valid email address" }),
	password: z
		.string()
		.min(8, { message: "Password must be at least 8 characters long" })
		.max(32, { message: "Password cannot exceed 32 characters" }),
});

export const userValidation = {
	PatientRegistrationZodSchema,
	PatientLoginZodSchema,
};
