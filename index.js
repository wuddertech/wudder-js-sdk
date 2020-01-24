import stringify from 'json-stable-stringify';
const Accounts = require('web3-eth-accounts');
const createApolloFetch = require('apollo-fetch').createApolloFetch;
const accounts = new Accounts();

const Wudder = {
    signup: async ({ email, password, privateKeyPassword = '', uri }) => {
        const account = accounts.create();
        const ethAccount = stringify(account.encrypt(privateKeyPassword));
        const wudderFetch = createApolloFetch({
            uri,
        });

        const response = await wudderFetch({
            query: `
                mutation createUser($user: UserInput!, $password: String!){
                    createUser(user: $user, password: $password){
                        id
                    }
                }
            `,
            variables: {
                user: {
                    email,
                    ethAccount
                },
                password
            }
        });

        return response;
    },

    initialize: async ({ email, password, uri, ethPassword }) => {     
        let token = null;
        let refreshToken = null;
        let account = null;
        let wudderFetch = null;

        wudderFetch = createApolloFetch({
            uri,
        });

        
        wudderFetch.use(({ request, options }, next) => {
            if (!options.headers) {
                options.headers = {};  // Create the headers object if needed.
            }
            options.headers['x-jwt-token'] = token;
            next();
        });

        const getWudderToken = async () => {
            const response = await wudderFetch({
                query: `
                    mutation login($email: String!, $password: String!){
                        login(email: $email, password: $password){
                            token
                            refreshToken
                            ethAccount
                        }
                    }
                `,
                variables: {
                    email,
                    password
                }
            });
            token = response.data.login.token;
            refreshToken = response.data.login.refreshToken;
        
            account = accounts.decrypt(response.data.login.ethAccount, ethPassword? ethPassword : '');

        }
        
        await getWudderToken();
        
        setInterval(getWudderToken, 20000000);

        const createEvidence = async (data, type) => {

        }


        return {
            getEvent: async evhash => {
                const response = await wudderFetch({
                    query: `
                        query Trace($evhash: String!){
                            evidence(evhash: $evhash){
                                id
                                displayName
                                evidence
                                evhash
                                originalContent
                            }
                        }
                    `,
                    variables: {
                        evhash
                    }
                });

                return response.data.evidence;
            },
            getTrace: async evhash => {
                const response = await wudderFetch({
                    query: `
                        query Trace($evhash: String!){
                            trace(evhash: $evhash){
                                creationEvidence {
                                    id
                                    displayName
                                    evidence
                                    evhash
                                    originalContent
                                }
                                childs {
                                    id
                                    displayName
                                    evidence
                                    evhash
                                    originalContent
                                }
                            }
                        }
                    `,
                    variables: {
                        evhash
                    }
                });
        
                return response.data.trace;
            }
        }
    }
}

export default Wudder;