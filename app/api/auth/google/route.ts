import { NextResponse } from "next/server";
import { OAuth2Client } from "google-auth-library";
import jwt from "jsonwebtoken";
import { connectToDatabase } from "@/lib/mongodb";
import bcrypt from "bcryptjs";

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

export async function POST(request: Request) {
  try {
    const { token } = await request.json();
    if (!token) {
      return NextResponse.json({ success: false, message: "No token provided" }, { status: 400 });
    }

    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    if (!payload) {
      return NextResponse.json({ success: false, message: "Invalid Google token" }, { status: 400 });
    }

    const { email, name, sub } = payload; // Google ID = "sub"

    const { db } = await connectToDatabase();
    let user = await db.collection("users").findOne({ email });

    if (!user) {

      const hashedPassword = await bcrypt.hash(sub, 10); // Hash Google ID for security

      await db.collection("users").insertOne({
        name,
        email,
        team_name: name,
        username: name,
        password: hashedPassword, // Store hashed Google ID as password
        isGoogleAuth: true,
        created_at: new Date(),
      });

      user = await db.collection("users").findOne({ email });
    }

    if (!user) {
      throw new Error("User not found");
    }
    
    const jwtToken = jwt.sign({ id: user._id, email: user.email, team_name: user.team_name }, process.env.JWT_SECRET!, {
      expiresIn: "7d",
    });

    const response = NextResponse.json({ success: true, message: "Login successful" });
    response.headers.set(
      "Set-Cookie",
      `token=${jwtToken}; HttpOnly; Secure; Path=/; Max-Age=${7 * 24 * 60 * 60}; jwt=`
    );

    return response;
  } catch (error) {
    console.error("Google Auth Error:", error);
    return NextResponse.json({ success: false, message: "Server error" }, { status: 500 });
  }
}
