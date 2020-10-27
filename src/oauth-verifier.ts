/**
 *    Copyright (c) ppy Pty Ltd <contact@ppy.sh>.
 *
 *    This file is part of osu!web. osu!web is distributed with the hope of
 *    attracting more community contributions to the core ecosystem of osu!.
 *
 *    osu!web is free software: you can redistribute it and/or modify
 *    it under the terms of the Affero GNU General Public License version 3
 *    as published by the Free Software Foundation.
 *
 *    osu!web is distributed WITHOUT ANY WARRANTY; without even the implied
 *    warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *    See the GNU Affero General Public License for more details.
 *
 *    You should have received a copy of the GNU Affero General Public License
 *    along with osu!web.  If not, see <http://www.gnu.org/licenses/>.
 */

import * as fs from 'fs';
import * as http from 'http';
import * as jwt from 'jsonwebtoken';
import * as mysql from 'mysql2/promise';
import * as url from 'url';

interface Params {
  baseDir: string;
  db: mysql.Pool;
}

interface OAuthJWT {
  aud: string; // oauth client id
  exp: number; // expires at
  iat: number; // issued at
  jti: string; // token id
  nbf: number; // valid after
  scopes: string[]; // oauth scopes
  sub: string; // user id
}

const isOAuthJWT = (arg: object|string): arg is OAuthJWT => {
  return typeof arg === 'object';
};

export default class OAuthVerifier {
  db: mysql.Pool;
  oAuthTokenSignatureKey: Buffer;

  constructor(params: Params) {
    this.db = params.db;
    this.oAuthTokenSignatureKey = fs.readFileSync(`${params.baseDir}/oauth-public.key`);
  }

  getToken = (req: http.IncomingMessage): void | OAuthJWT => {
    let token;
    const authorization = req.headers.authorization;

    // no authorization header, try from query string
    if (authorization == null) {
      if (req.url == null) {
        return;
      }

      const params = url.parse(req.url, true).query;

      if (typeof params.access_token === 'string') {
        token = params.access_token;
      }
    } else {
      const matches = authorization.match(/^Bearer (.+)$/);

      if (matches != null) {
        token = matches[1];
      }
    }

    if (token == null) {
      return;
    }

    const parsedToken = jwt.verify(token, this.oAuthTokenSignatureKey);

    if (isOAuthJWT(parsedToken)) {
      return parsedToken;
    }
  }

  verifyRequest = async (req: http.IncomingMessage) => {
    const oAuthToken = this.getToken(req);

    if (oAuthToken == null) {
      return null;
    }

    const [rows] = await this.db.execute<mysql.RowDataPacket[]>(`
      SELECT user_id, scopes, expires_at
      FROM oauth_access_tokens
      WHERE revoked = false
        AND expires_at > now()
        AND id = ?
        AND user_id = ?
        AND client_id = ?
    `, [
      oAuthToken.jti,
      // This will be empty string for tokens without user id (client grants)
      // and thus prevent them from connecting.
      oAuthToken.sub,
      oAuthToken.aud,
    ]);

    if (rows.length === 0) {
      throw new Error('token doesn\'t exist');
    }

    const expiresAt: Date = rows[0].expires_at;
    const scopes: string[] = JSON.parse(rows[0].scopes);
    const userId: number = rows[0].user_id;

    for (const scope of scopes) {
      if (scope === '*' || scope === 'read') {
        return {
          expiresAt,
          key: `oauth:${oAuthToken.jti}`,
          requiresVerification: false,
          userId,
          verified: false,
        };
      }
    }

    throw new Error('token doesn\'t have the required scope');
  }
}
