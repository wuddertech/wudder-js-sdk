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
        
        getWudderToken();
        
        setInterval(getWudderToken, 20000000);
    }
}

//class Wudder {
 

    

    // async signup () {
    //     const response = await wudderFetch({
    //         query: `
    //             mutation createUser($user: UserInput!, $password: String!){
    //                 createUser(user: $user, password: $password){
    //                     id
    //                 }
    //             }
    //         `,
    //         variables: {
    //             user: {
    //                 name: 'claudia',
    //                 surname: '',
    //                 email: 'info@weareclaudia.com'
    //             },
    //             password: 'Claudia_2019com'
    //         }
    //     });
    // }




    // createEvidence: async (data, displayName) => {
    //     const response = await wudderFetch({
    //         query: `
    //             mutation FormatEvidence($content: String!, $displayName: String!){
    //                 formatEvidence(content: $content, displayName: $displayName){
    //                     formattedEvidence
    //                     preparedContent
    //                     hash
    //                 }
    //             }
    //         `,
    //         variables: {
    //             content: stringify({
    //                 type: data.type,
    //                 trace: data.trace,
    //                 fragments: data.fragments,
    //                 descriptor: []
    //             }),
    //             displayName
    //         }
    //     });

    //     const formatEvidence = response.data.formatEvidence;

    //     const signedContent = account.sign(formatEvidence.formattedEvidence);

    //     const evidence = {
    //         event_tx: signedContent.message,
    //         signature: signedContent.signature.substring(2)
    //     };

    //     const result = await wudderFetch({
    //         query: `
    //             mutation CreateEvidence($evidence: EvidenceInput!, $hash: String!){
    //                 createEvidence(evidence: $evidence, hash: $hash){
    //                     id
    //                     evhash
    //                     evidence
    //                     originalEvidence
    //                 }
    //             }
    //         `,
    //         variables: {
    //             evidence,
    //             hash: formatEvidence.hash
    //         }
    //     });

    //     return result;

    // },

    // getEvidence: async evhash => {
    //     const response = await wudderFetch({
    //         query: `
    //             query Trace($evhash: String!){
    //                 evidence(evhash: $evhash){
    //                     id
    //                     displayName
    //                     evidence
    //                     evhash
    //                     originalEvidence
    //                 }
    //             }
    //         `,
    //         variables: {
    //             evhash
    //         }
    //     });

    //     return response.data.evidence;
    // },

    // getTrace: async evhash => {
    //     const response = await wudderFetch({
    //         query: `
    //             query Trace($evhash: String!){
    //                 trace(evhash: $evhash){
    //                     creationEvidence {
    //                         id
    //                         displayName
    //                         evidence
    //                         evhash
    //                         originalEvidence
    //                     }
    //                     childs {
    //                         id
    //                         displayName
    //                         evidence
    //                         evhash
    //                         originalEvidence
    //                     }
    //                 }
    //             }
    //         `,
    //         variables: {
    //             evhash
    //         }
    //     });

    //     return response.data.trace;
    // },

    // getMyTraces: async () => {
    //     const response = await wudderFetch({
    //         query: `
    //             query MyTraces{
    //                 myTraces{
    //                     id
    //                     displayName
    //                     evidence
    //                     evhash
    //                     originalEvidence
    //                 }
    //             }
    //         `
    //     });

    //     if(response.data){
    //         return response.data.myTraces;
    //     }

    //     return response.errors;
    // }
//}

export default Wudder;