
import { APIGatewayEvent, Callback, Context, CustomAuthorizerEvent, Handler } from "aws-lambda";
import * as jwt from "jsonwebtoken";
const secret = "34JWXb6HSt";

export const customAuthorizer: Handler = async (event: CustomAuthorizerEvent, context: Context, cb: Callback) => {
    const authToken = event.authorizationToken;
    if (!authToken || authToken.split(" ")[0] !== "Bearer") {
        cb(new Error("Authorization token missing or malformed"));
    } else {
        try {
            const token = authToken.split(" ")[1];
            const decoded = jwt.decode(token, secret);
            const username = decoded.username;
            const expired = decoded.exp as number;
            const effect = authorize(username, expired) ? "Allow" : "Deny";
            const authorizerContext = { user: username };
            const policyDocument = buildIAMPolicy(
                username, effect, "*", authorizerContext);
            cb(null, policyDocument);
        } catch (e) {
            cb(new Error("Unauthorized: " + e));
        }
    }
};

function authorize(username: string, expired: number): boolean {
    // for the sake of example, we always authorize, but here's the place to do the user verification
    return true;
}

function buildIAMPolicy(userId: string, effect: string, resource: string, context: any) {
    return {
        context,

        policyDocument: {
            Statement: [
                {
                    Action: "execute-api:Invoke",
                    Effect: effect,
                    Resource: resource,
                },
            ],
            Version: "2012-10-17",
        },
        principalId: userId,
    };
}
