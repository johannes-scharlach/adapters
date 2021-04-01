import { AppOptions, SessionOptions } from 'next-auth';
import { query as q, Client as FaunaClient } from 'faunadb';
import { createHash, randomBytes } from 'crypto';
import { AdapterInstance, EmailAppProvider } from 'next-auth/adapters';
export interface IFaunaAdapterConfig {
    faunaClient: FaunaClient;
    collections?: {
        User: string;
        Account: string;
        Session: string;
        VerificationRequest: string;
    };
    indexes?: {
        Account: string;
        User: string;
        Session: string;
        VerificationRequest: string;
    };
}

interface Profile {
    name: string;
    email: string;
    image: string;
    emailVerified: Date;
    username: string;
}

interface UserData {
    name: string;
    email: string;
    image: string;
    emailVerified: Date | null;
    username: string;
    createdAt: Date;
    updatedAt: Date;
}

interface User extends UserData {
    id: string;
}

interface UserQueryResult {
    ref: { id: string };
    data: UserData & {
        emailVerified: { value: string } | null;
        createdAt: { value: string };
        updatedAt: { value: string };
    };
}
interface SessionData {
    userId: string;
    expires: Date;
    sessionToken: string;
    accessToken: string;
    createdAt: Date;
    updatedAt: Date;
}

interface Session extends SessionData {
    id: string;
}

interface SessionQueryResult {
    ref: { id: string };
    data: SessionData & {
        expires: { value: string };
        createdAt: { value: string };
        updatedAt: { value: string };
    };
}

interface VerificationRequestData {
    identifier: string;
    token: string;
    expires: Date | null;
    createdAt: Date;
    updatedAt: Date;
}
interface VerificationRequest extends VerificationRequestData {
    id: string;
}

interface VerificationRequestQueryResult {
    ref: { id: string };
    data: VerificationRequestData & {
        expires: { value: string } | null;
        createdAt: { value: string };
        updatedAt: { value: string };
    };
}

function FaunaAdapter(
    config: IFaunaAdapterConfig,
    options = {},
): {
    getAdapter: (
        appOptions: Partial<AppOptions>,
    ) => Promise<AdapterInstance<User, Profile, Session, VerificationRequest>>;
} {
    const {
        faunaClient,
        collections = {
            User: 'users',
            Account: 'accounts',
            Session: 'sessions',
            VerificationRequest: 'verification_requests',
        },
        indexes = {
            Account: 'account_by_provider_account_id',
            User: 'user_by_email',
            Session: 'session_by_token',
            VerificationRequest: 'verification_request_by_token',
        },
    } = config;

    async function getAdapter(
        appOptions: Partial<
            AppOptions & {
                session?: SessionOptions;
            }
        >,
    ): Promise<AdapterInstance<User, Profile, Session, VerificationRequest>> {
        const { logger } = appOptions;

        const defaultSessionMaxAge = 30 * 24 * 60 * 60;
        const sessionMaxAge = (appOptions.session?.maxAge ?? defaultSessionMaxAge) * 1000;
        const sessionUpdateAge = (appOptions.session?.updateAge ?? 0) * 1000;

        async function createUser(profile: Profile): Promise<User> {
            logger?.debug('create_user', profile);

            const FQL = q.Create(q.Collection(collections.User), {
                data: {
                    name: profile.name,
                    email: profile.email,
                    image: profile.image,
                    emailVerified: profile.emailVerified ? q.Time(profile.emailVerified.toISOString()) : null,
                    username: profile.username,
                    createdAt: q.Now(),
                    updatedAt: q.Now(),
                },
            });

            try {
                const { ref, data: user } = (await faunaClient.query<UserQueryResult>(FQL)) || {};

                const result = {
                    ...user,
                    id: ref.id,
                    emailVerified: user.emailVerified ? new Date(user.emailVerified.value) : null,
                    createdAt: new Date(user.createdAt.value),
                    updatedAt: new Date(user.updatedAt.value),
                };

                logger?.debug('create_user_result', result);
                return result;
            } catch (error) {
                logger?.error('create_user_error', error);
                return Promise.reject(new Error('create_user_error'));
            }
        }

        async function getUser(id: string): Promise<User> {
            logger?.debug('get_user', id);

            const FQL = q.Get(q.Ref(q.Collection(collections.User), id));

            try {
                const { ref, data: user } = (await faunaClient.query<UserQueryResult>(FQL)) || {};

                const result = {
                    ...user,
                    id: ref.id,
                    emailVerified: user.emailVerified ? new Date(user.emailVerified.value) : null,
                    createdAt: new Date(user.createdAt.value),
                    updatedAt: new Date(user.updatedAt.value),
                };

                logger?.debug('get_user_result', result);
                return result;
            } catch (error) {
                logger?.error('get_user_error', error);
                return Promise.reject(new Error('get_user_error'));
            }
        }

        async function getUserByEmail(email: string): Promise<User | null> {
            logger?.debug('get_user_by_email', email);

            if (!email) {
                return null;
            }

            const FQL = q.Let(
                {
                    ref: q.Match(q.Index(indexes.User), email),
                },
                q.If(q.Exists(q.Var('ref')), q.Get(q.Var('ref')), null),
            );

            try {
                const { ref, data: user } = (await faunaClient.query<UserQueryResult>(FQL)) || {};

                if (!user) {
                    return null;
                }

                const result = {
                    ...user,
                    id: ref.id,
                    emailVerified: user.emailVerified ? new Date(user.emailVerified.value) : null,
                    createdAt: new Date(user.createdAt.value),
                    updatedAt: new Date(user.updatedAt.value),
                };

                logger?.debug('get_user_by_email_result', result);
                return result;
            } catch (error) {
                logger?.error('get_user_by_email_error', error);
                return Promise.reject(new Error('get_user_by_email_error'));
            }
        }

        async function getUserByProviderAccountId(providerId: string, providerAccountId: string): Promise<User | null> {
            logger?.debug('get_user_by_provider_account_id', providerId, providerAccountId);

            const FQL = q.Let(
                {
                    ref: q.Match(q.Index(indexes.Account), [providerId, providerAccountId]),
                },
                q.If(
                    q.Exists(q.Var('ref')),
                    q.Get(q.Ref(q.Collection(collections.User), q.Select(['data', 'userId'], q.Get(q.Var('ref'))))),
                    null,
                ),
            );

            try {
                const { ref, data: user } = (await faunaClient.query<UserQueryResult>(FQL)) || {};

                if (!user) {
                    return null;
                }

                const result = {
                    ...user,
                    id: ref.id,
                    emailVerified: user.emailVerified ? new Date(user.emailVerified.value) : null,
                    createdAt: new Date(user.createdAt.value),
                    updatedAt: new Date(user.updatedAt.value),
                };

                logger?.debug('get_user_by_provider_account_id_result', result);
                return result;
            } catch (error) {
                logger?.error('get_user_by_provider_account_id_error', error);
                return Promise.reject(new Error('get_user_by_provider_account_id_error'));
            }
        }

        async function updateUser(user: User): Promise<User> {
            logger?.debug('update_user', user);

            const FQL = q.Update(q.Ref(q.Collection(collections.User), user.id), {
                data: {
                    name: user.name,
                    email: user.email,
                    image: user.image,
                    emailVerified: user.emailVerified ? q.Time(user.emailVerified.toISOString()) : null,
                    username: user.username,
                    updatedAt: q.Now(),
                },
            });

            try {
                const { ref, data: updatedUser } = (await faunaClient.query<UserQueryResult>(FQL)) || {};

                const result = {
                    ...updatedUser,
                    id: ref.id,
                    emailVerified: updatedUser.emailVerified ? new Date(updatedUser.emailVerified.value) : null,
                    createdAt: new Date(updatedUser.createdAt.value),
                    updatedAt: new Date(updatedUser.updatedAt.value),
                };

                logger?.debug('update_user_result', result);
                return result;
            } catch (error) {
                logger?.error('update_user_error', error);
                return Promise.reject(new Error('update_user_error'));
            }
        }

        async function deleteUser(userId: string): Promise<void> {
            logger?.debug('delete_user', userId);

            const FQL = q.Delete(q.Ref(q.Collection(collections.User), userId));

            try {
                return await faunaClient.query(FQL);
            } catch (error) {
                logger?.error('delete_user_error', error);
                return Promise.reject(new Error('delete_user_error'));
            }
        }

        async function linkAccount(
            userId: string,
            providerId: string,
            providerType: string,
            providerAccountId: string,
            refreshToken: string,
            accessToken: string,
            accessTokenExpires: number,
        ): Promise<void> {
            logger?.debug(
                'link_account',
                userId,
                providerId,
                providerType,
                providerAccountId,
                refreshToken,
                accessToken,
                accessTokenExpires,
            );

            const FQL = q.Create(q.Collection(collections.Account), {
                data: {
                    userId: userId,
                    providerId: providerId,
                    providerType: providerType,
                    providerAccountId: providerAccountId,
                    refreshToken: refreshToken,
                    accessToken: accessToken,
                    accessTokenExpires: accessTokenExpires,
                    createdAt: q.Now(),
                    updatedAt: q.Now(),
                },
            });

            try {
                return await faunaClient.query(FQL);
            } catch (error) {
                logger?.error('link_account_error', error);
                return Promise.reject(new Error('link_account_error'));
            }
        }

        async function unlinkAccount(userId: string, providerId: string, providerAccountId: string): Promise<void> {
            logger?.debug('unlink_account', userId, providerId, providerAccountId);

            const FQL = q.Delete(
                q.Select('ref', q.Get(q.Match(q.Index(indexes.Account), [providerId, providerAccountId]))),
            );

            try {
                return await faunaClient.query(FQL);
            } catch (error) {
                logger?.error('unlink_account_error', error);
                return Promise.reject(new Error('unlink_account_error'));
            }
        }

        async function createSession(user: User): Promise<Session> {
            logger?.debug('create_session', user);

            const dateExpires = new Date();
            dateExpires.setTime(dateExpires.getTime() + sessionMaxAge);
            const expires = dateExpires.toISOString();

            const FQL = q.Create(q.Collection(collections.Session), {
                data: {
                    userId: user.id,
                    expires: q.Time(expires),
                    sessionToken: randomBytes(32).toString('hex'),
                    accessToken: randomBytes(32).toString('hex'),
                    createdAt: q.Now(),
                    updatedAt: q.Now(),
                },
            });

            try {
                const { ref, data: session } = (await faunaClient.query<SessionQueryResult>(FQL)) || {};

                const result = {
                    ...session,
                    id: ref.id,
                    expires: new Date(session.expires.value),
                    createdAt: new Date(session.createdAt.value),
                    updatedAt: new Date(session.updatedAt.value),
                };

                logger?.debug('create_session_result', result);
                return result;
            } catch (error) {
                logger?.error('create_session_error', error);
                return Promise.reject(new Error('create_session_error'));
            }
        }

        async function getSession(sessionToken: string): Promise<Session | null> {
            logger?.debug('get_session', sessionToken);

            const FQL = q.Let(
                {
                    ref: q.Match(q.Index(indexes.Session), sessionToken),
                },
                q.If(q.Exists(q.Var('ref')), q.Get(q.Var('ref')), null),
            );

            try {
                const { ref, data: session } = (await faunaClient.query<SessionQueryResult>(FQL)) || {};

                if (!session) {
                    return null;
                }

                // Check session has not expired (do not return it if it has)
                if (session.expires && Date.now() > Date.parse(session.expires.value)) {
                    await faunaClient.query(q.Delete(ref));
                    return null;
                }

                const result = {
                    ...session,
                    id: ref.id,
                    expires: new Date(session.expires.value),
                    createdAt: new Date(session.createdAt.value),
                    updatedAt: new Date(session.updatedAt.value),
                };

                logger?.debug('get_session_result', result);
                return result;
            } catch (error) {
                logger?.error('get_session_error', error);
                return Promise.reject(new Error('get_session_error'));
            }
        }

        async function updateSession(session: Session, force: boolean): Promise<Session | null> {
            logger?.debug('update_session', session);

            const shouldUpdate = sessionMaxAge && (sessionUpdateAge || sessionUpdateAge === 0) && session.expires;
            if (!shouldUpdate && !force) {
                return null;
            }

            // Calculate last updated date, to throttle write updates to database
            // Formula: ({expiry date} - sessionMaxAge) + sessionUpdateAge
            //     e.g. ({expiry date} - 30 days) + 1 hour
            //
            // Default for sessionMaxAge is 30 days.
            // Default for sessionUpdateAge is 1 hour.
            const dateSessionIsDueToBeUpdated = new Date(session.expires);
            dateSessionIsDueToBeUpdated.setTime(dateSessionIsDueToBeUpdated.getTime() - sessionMaxAge);
            dateSessionIsDueToBeUpdated.setTime(dateSessionIsDueToBeUpdated.getTime() + sessionUpdateAge);

            // Trigger update of session expiry date and write to database, only
            // if the session was last updated more than {sessionUpdateAge} ago
            if (new Date() < dateSessionIsDueToBeUpdated && !force) {
                return null;
            }

            const newExpiryDate = new Date();
            newExpiryDate.setTime(newExpiryDate.getTime() + sessionMaxAge);

            const FQL = q.Update(q.Ref(q.Collection(collections.Session), session.id), {
                data: {
                    expires: q.Time(newExpiryDate.toISOString()),
                    updatedAt: q.Time(new Date().toISOString()),
                },
            });

            try {
                const { ref, data: updatedSession } = (await faunaClient.query<SessionQueryResult>(FQL)) || {};

                const result = {
                    ...updatedSession,
                    id: ref.id,
                    expires: new Date(updatedSession.expires.value),
                    createdAt: new Date(updatedSession.createdAt.value),
                    updatedAt: new Date(updatedSession.updatedAt.value),
                };

                logger?.debug('update_session_result', result);
                return result;
            } catch (error) {
                logger?.error('update_session_error', error);
                return Promise.reject(new Error('update_session_error'));
            }
        }

        async function deleteSession(sessionToken: string): Promise<void> {
            logger?.debug('delete_session', sessionToken);

            const FQL = q.Delete(q.Select('ref', q.Get(q.Match(q.Index(indexes.Session), sessionToken))));

            try {
                return await faunaClient.query(FQL);
            } catch (error) {
                logger?.error('delete_session_error', error);
                return Promise.reject(new Error('delete_session_error'));
            }
        }

        async function createVerificationRequest(
            identifier: string,
            url: string,
            token: string,
            secret: string,
            provider: EmailAppProvider,
        ): Promise<VerificationRequest | null> {
            logger?.debug('create_verification_request', identifier);

            const { baseUrl } = appOptions;
            const { sendVerificationRequest, maxAge } = provider;

            if (!baseUrl) {
                return null;
            }

            // Store hashed token (using secret as salt) so that tokens cannot be exploited
            // even if the contents of the database is compromised
            // @TODO Use bcrypt function here instead of simple salted hash
            const hashedToken = createHash('sha256').update(`${token}${secret}`).digest('hex');

            let expires = null;
            if (maxAge) {
                const dateExpires = new Date();
                dateExpires.setTime(dateExpires.getTime() + maxAge * 1000);

                expires = dateExpires.toISOString();
            }

            const FQL = q.Create(q.Collection(collections.VerificationRequest), {
                data: {
                    identifier: identifier,
                    token: hashedToken,
                    expires: expires ? q.Time(expires) : null,
                    createdAt: q.Now(),
                    updatedAt: q.Now(),
                },
            });

            try {
                const { ref, data: verificationRequest } =
                    (await faunaClient.query<VerificationRequestQueryResult>(FQL)) || {};

                // With the verificationCallback on a provider, you can send an email, or queue
                // an email to be sent, or perform some other action (e.g. send a text message)
                await sendVerificationRequest({
                    identifier,
                    url,
                    token,
                    baseUrl,
                    provider,
                });

                const result = {
                    ...verificationRequest,
                    id: ref.id,
                    expires: verificationRequest.expires ? new Date(verificationRequest.expires.value) : null,
                    createdAt: new Date(verificationRequest.createdAt.value),
                    updatedAt: new Date(verificationRequest.updatedAt.value),
                };

                logger?.debug('create_verification_request_result', result);
                return result;
            } catch (error) {
                logger?.error('create_verification_request_error', error);
                return Promise.reject(new Error('create_verification_request_error'));
            }
        }

        async function getVerificationRequest(
            identifier: string,
            token: string,
            secret: string,
            provider: unknown,
        ): Promise<VerificationRequest | null> {
            logger?.debug('get_verification_request', identifier, token);

            const hashedToken = createHash('sha256').update(`${token}${secret}`).digest('hex');

            const FQL = q.Let(
                {
                    ref: q.Match(q.Index(indexes.VerificationRequest), hashedToken),
                },
                q.If(q.Exists(q.Var('ref')), q.Get(q.Var('ref')), null),
            );

            try {
                const { ref, data: verificationRequest } =
                    (await faunaClient.query<VerificationRequestQueryResult>(FQL)) || {};

                if (!verificationRequest) {
                    return null;
                }

                if (verificationRequest.expires && Date.now() > Date.parse(verificationRequest.expires.value)) {
                    // Delete the expired request so it cannot be used
                    await faunaClient.query(q.Delete(ref));
                    return null;
                }

                const result = {
                    ...verificationRequest,
                    id: ref.id,
                    expires: verificationRequest.expires ? new Date(verificationRequest.expires.value) : null,
                    createdAt: new Date(verificationRequest.createdAt.value),
                    updatedAt: new Date(verificationRequest.updatedAt.value),
                };

                logger?.debug('get_verification_request_result', result);
                return result;
            } catch (error) {
                logger?.error('get_verification_request_error', error);
                return Promise.reject(new Error('get_verification_request_error'));
            }
        }

        async function deleteVerificationRequest(
            identifier: string,
            token: string,
            secret: string,
            provider: unknown,
        ): Promise<void> {
            logger?.debug('delete_verification_request', identifier, token);

            const hashedToken = createHash('sha256').update(`${token}${secret}`).digest('hex');
            const FQL = q.Delete(q.Select('ref', q.Get(q.Match(q.Index(indexes.VerificationRequest), hashedToken))));

            try {
                return await faunaClient.query(FQL);
            } catch (error) {
                logger?.error('delete_verification_error', error);
                return Promise.reject(new Error('delete_verification_error'));
            }
        }

        return {
            createUser,
            getUser,
            getUserByEmail,
            getUserByProviderAccountId,
            updateUser,
            deleteUser,
            linkAccount,
            unlinkAccount,
            createSession,
            getSession,
            updateSession,
            deleteSession,
            createVerificationRequest,
            getVerificationRequest,
            deleteVerificationRequest,
        } as AdapterInstance<User, Profile, Session, VerificationRequest>;
    }

    return {
        getAdapter,
    };
}

export default FaunaAdapter;
