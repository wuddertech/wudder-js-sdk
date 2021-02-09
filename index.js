const stringify = require('json-stable-stringify');
const { getRootHash } = require('wudder-js/utils');
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

    initialize: async ({ email, password, uri, ethPassword, token: newToken = null, refreshToken: newRefreshToken = null }) => {
        let token = newToken;
        let refreshToken = newRefreshToken;
        let account = null;
        let wudderFetch = null;

        wudderFetch = createApolloFetch({
            uri,
        });

        wudderFetch.use(({ request, options }, next) => {
            if (!options.headers) {
                options.headers = {};
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

            if(response.data.login.ethAccount && ethPassword){
                account = accounts.decrypt(response.data.login.ethAccount, ethPassword? ethPassword : '');
            }
        }

        const getNewToken = async refresh => {
            const response = await wudderFetch({
                query: `
                    mutation refreshToken($token: String!){
                        refreshToken(token: $token){
                            token
                            refreshToken
                        }
                    }
                `,
                variables: {
                    token: refresh
                }
            });


            token = response.data.refreshToken.token;
            refreshToken = response.data.refreshToken.refreshToken;


            setTimeout(() => getNewToken(response.data.refreshToken.refreshToken), 20000000);
        }

        if(!token){
            await getWudderToken();
        }

        if(token && !account && ethPassword){
            if(!account){
                const meResponse = await wudderFetch({
                    query: `
                        query me{
                            me {
                                ethAccount
                            }
                        }
                    `
                });
               account = accounts.decrypt(meResponse.data.me.ethAccount, ethPassword? ethPassword : '');
            }

        }

        setTimeout(() => getNewToken(refreshToken), 20000000);

        const createEvidence = async ({
            fragments,
            trace,
            displayName
        }, type) => {
            const result = await wudderFetch({
                query: `
                    mutation CreateEvidence($evidence: EvidenceInput!, $displayName: String!){
                        createEvidence(evidence: $evidence, displayName: $displayName){
                            id
                            evhash
                            creationDate
                            displayName
                            originalContent
                        }
                    }
                `,
                variables: {
                    evidence: {
                        content: {
                            type,
                            trace,
                            fragments,
                            descriptor: [],
                            timestamp: new Date().getTime()
                        },
                    },
                    displayName
                }
            });
            return result;
        }

        const getEvent = async evhash => {
            const response = await wudderFetch({
                query: `
                    query Trace($evhash: String!){
                        evidence(evhash: $evhash){
                            id
                            displayName
                            evhash
                            graphnData
                            originalContent
                        }
                    }
                `,
                variables: {
                    evhash
                }
            });

            if(response.errors){
                throw new Error(response.errors[0].message);
            }

            return response.data.evidence;
        }


        return {
            getEvent,
            getTrace: async evhash => {
                const response = await wudderFetch({
                    query: `
                        query Trace($evhash: String!){
                            trace(evhash: $evhash){
                                creationEvidence {
                                    id
                                    creationDate
                                    displayName
                                    evhash
                                    originalContent
                                }
                                childs {
                                    id
                                    displayName
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

                return response;
            },
            createTrace: async data => {
                const result = await createEvidence(data, 'TRACE');
                return result;
            },
            createFileEvidence: async data => {
                const result = await createEvidence(data, 'FILE');
                return result;
            },

            createPreparedEvidence: async ({
                fragments,
                trace,
                displayName
            }, type) => {
                const response = await wudderFetch({
                    query: `
                        mutation createPreparedEvidence($content: ContentInput!, $displayName: String!){
                            createPreparedEvidence(content: $content, displayName: $displayName){
                                formattedTransaction
                                preparedContent
                            }
                        }
                    `,
                    variables: {
                        content: {
                            type,
                            trace,
                            fragments,
                            descriptor: []
                        },
                        displayName
                    }
                });
    
                return response.data.preparedEvidence;
            },

            preparedEvidence: async hash => {
                const response = await wudderFetch({
                    query: `
                        query preparedEvidence($hash: String!){
                            preparedEvidence(hash: $hash){
                                formattedTransaction
                                preparedContent
                            }
                        }
                    `,
                    variables: {
                        hash
                    }
                });

                return response;
            },

            confirmPreparedEvidence: async preparedEvidence => {

                let signature = '';

                if(account){
                    const signedContent = account.sign(preparedEvidence.formattedTransaction);   
                    signature = signedContent.signature.substring(2)
                }
    
                // const evidence = {
                //     event_tx: signedContent.message,
                //     signature: signedContent.signature.substring(2)
                // };
    
                const result = await wudderFetch({
                    query: `
                        mutation ConfirmPreparedEvidence($evidence: PreparedEvidenceInput!){
                            confirmPreparedEvidence(evidence: $evidence){
                                id
                                evhash
                                originalContent
                            }
                        }
                    `,
                    variables: {
                        evidence: {
                            preparedEvidence: preparedEvidence.formattedTransaction,
                            signature
                        }
                    }
                });
    
                return result;
            },

            addEvent: async data => {
                const result = await createEvidence(data, 'ADD_EVENT');
                return result;
            },
            getProof: async evhash => {
                const evidence = await getEvent(evhash);

                const graphnData = JSON.parse(evidence.graphnData);

                let proof = {
                    graphnProof: graphnData.proof
                }

                if(graphnData.prefixes && graphnData.prefixes.ethereum){
                    proof.anchorTxs = Object.keys(graphnData.prefixes).reduce((acc, curr) => {
                        acc[curr] = graphnData.prefixes[curr].tx_hash;
                        return acc;
                    }, {});
                }
                return proof;
            },
            checkEthereumProof: async (proof, ethereumEndpoint = 'https://cloudflare-eth.com/') => {
                const rootHash = getRootHash(proof.graphnProof);
                const response = await fetch(ethereumEndpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        "jsonrpc": "2.0", "method": "eth_getTransactionByHash", "params": [proof.anchorTxs.ethereum], "id": 1
                    })
                });
                const json = await response.json();
                return rootHash === json.result.input.substring(2);
            },

            myTraces: async (options, type) => {
                if(!options){
                    throw new Error('The pagination options are required');
                }

                if(options.offset === undefined || options.offset === null || options.offset < 0){
                    throw new Error('Invalid offset');
                }

                if(!options.limit || options.limit > 20 || options <= 0){
                    throw new Error('Invalid limit, it only accepts values between 1 and 20');
                }
                if(type !== 'TRACE' && type !== 'FILE'){
                    throw new Error('Invalid type');
                }

                const response = await wudderFetch({
                    query: `query MyTraces($options: OptionsInput, $type: String!){
                        myTraces(options: $options, type: $type){
                            list {
                                id
                                displayName
                                creationDate
                                evhash
                                originalContent
                            }
                            total
                        }
                    }`,
                    variables: {
                        options,
                        type
                    }
                });

                return response;
            },

            trace: async evhash => {
                const response = await wudderFetch({
                    query: `query trace($evhash: String!){
                        trace(evhash: $evhash){
                            creationEvidence {
                                id
                                creationDate
                                displayName
                                graphnData
                                evhash
                                originalContent
                            }
                            childs {
                                id
                                displayName
                                graphnData
                                evhash
                                creationDate
                                originalContent
                            }
                        }
                    }`,
                    variables: {
                        evhash
                    }
                });

                return response;
            }

        }
    }
}


module.exports = Wudder;
