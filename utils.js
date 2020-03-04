const { sha3_512 } = require('js-sha3');
const blake = require('blakejs');
const stringify = require('json-stable-stringify');

module.exports.mtk_512 = string => {
    return blake.blake2bHex(sha3_512(string) + string);
}

module.exports.mtk_256 = string => {
    return blake.blake2bHex(sha3_512(string) + string, undefined, 32);
}

module.exports.createHashes = string => {
    const prvhash = mtk_512(string);
    return {
        prvhash,
        evhash: mtk_256(prvhash)
    }
}

module.exports.ctHashFromContent = content => {
    const data = stringify({
        type: content.type,
        trace: content.trace,
        fragment_hashes: content.fragments.map(fragment => {
            return mtk_512(stringify(fragment));
        }).sort(),
        descriptor: content.descriptor,
        salt: content.salt
    });

    return mtk_512(data);
}

module.exports.getRootHash = proof => {
    if(proof.length < 65){
        return {
            valid: false
        }
    }
    const rootHash = proof.substring(proof.length - 64);
    proof = proof.substring(0, proof.length - 64);

    const items = proof.match(/.{65}/g);

    let currentHash;
    let startIndex = 2;
    if(items[0][0] == 'l'){
        currentHash = mtk_256(items[0].substring(1) + items[1].substring(1));
    } else if(items[0][0] == 'r'){
        currentHash = mtk_256(items[0].substring(1) + items[1].substring(1));
    } else if (items[0][0] == 'o'){
        currentHash = mtk_256(items[0].substring(1));
        startIndex = 1;
    } else {
        return {'valid': false}
    }

    for(let i = startIndex; i < items.length; i++){
        if(items[i][0] == 'l'){
            currentHash = mtk_256(items[i].substring(1) + currentHash);
        } else if(items[i][0] == 'r'){
            currentHash = mtk_256(currentHash + items[i].substring(1));
        } else if (items[i][0] == 'o'){
            currentHash = mtk_256(currentHash);
        } else {
            return {'valid': false}
        }
    }

    if (currentHash === rootHash){
        return rootHash;
    }

    return null;

}