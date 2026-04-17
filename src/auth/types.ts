import { z } from "zod";

export const GitHubUserSchema = z.object({
  id: z.number(),
  login: z.string(),
  email: z.string().nullable().optional(),
});

export type GitHubUser = z.infer<typeof GitHubUserSchema>;

export const AuthPropsSchema = z.object({
  accessToken: z.string(),
  user: GitHubUserSchema,
  refreshToken: z.string().optional(),
});

export type AuthProps = z.infer<typeof AuthPropsSchema>;
