//! RFC 9497 Appendix A.1.2 vectors (ristretto255-SHA512, VOPRF mode) against the pinned `voprf`
//! release. The SDK's OPRF client is a thin wrapper over this library, and its blinds are always
//! random, so the vectors are checked here, at the library level: bumping the `voprf` pin must keep
//! them passing.

use voprf::{EvaluationElement, Group, Proof, Ristretto255, VoprfClient};

const PK_SM: &str = "c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e";
const BLIND_1: &str = "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706";
const BLIND_2: &str = "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e";
const INPUT_1: &str = "00";
const INPUT_2: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const OUTPUT_1: &str = "b58cfbe118e0cb94d79b5fd6a6dafb98764dff49c14e1770b566e42402da1a7d\
                        a4d8527693914139caee5bd03903af43a491351d23b430948dd50cde10d32b3c";
const OUTPUT_2: &str = "8a9a2f3c7f085b65933594309041fc1898d42d0858e59f90814ae90571a6df60\
                        356f4610bf816f27afdd84f47719e480906d27ecd994985890e5f539e7ea74b6";

struct Vector {
    inputs: Vec<&'static str>,
    blinds: Vec<&'static str>,
    blinded: Vec<&'static str>,
    evaluated: Vec<&'static str>,
    proof: &'static str,
    outputs: Vec<&'static str>,
}

fn vectors() -> Vec<Vector> {
    vec![
        Vector {
            inputs: vec![INPUT_1],
            blinds: vec![BLIND_1],
            blinded: vec!["863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945"],
            evaluated: vec!["aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e"],
            proof: "ddef93772692e535d1a53903db24367355cc2cc78de93b3be5a8ffcc6985dd06\
                    6d4346421d17bf5117a2a1ff0fcb2a759f58a539dfbe857a40bce4cf49ec600d",
            outputs: vec![OUTPUT_1],
        },
        Vector {
            inputs: vec![INPUT_2],
            blinds: vec![BLIND_1],
            blinded: vec!["cc0b2a350101881d8a4cba4c80241d74fb7dcbfde4a61fde2f91443c2bf9ef0c"],
            evaluated: vec!["60a59a57208d48aca71e9e850d22674b611f752bed48b36f7a91b372bd7ad468"],
            proof: "401a0da6264f8cf45bb2f5264bc31e109155600babb3cd4e5af7d181a2c9dc0a\
                    67154fabf031fd936051dec80b0b6ae29c9503493dde7393b722eafdf5a50b02",
            outputs: vec![OUTPUT_2],
        },
        Vector {
            inputs: vec![INPUT_1, INPUT_2],
            blinds: vec![BLIND_1, BLIND_2],
            blinded: vec![
                "863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945",
                "90a0145ea9da29254c3a56be4fe185465ebb3bf2a1801f7124bbbadac751e654",
            ],
            evaluated: vec![
                "aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e",
                "cc5ac221950a49ceaa73c8db41b82c20372a4c8d63e5dded2db920b7eee36a2a",
            ],
            proof: "cc203910175d786927eeb44ea847328047892ddf8590e723c37205cb74600b0a\
                    5ab5337c8eb4ceae0494c2cf89529dcf94572ed267473d567aeed6ab873dee08",
            outputs: vec![OUTPUT_1, OUTPUT_2],
        },
    ]
}

fn hex(value: &str) -> Vec<u8> {
    let value: String = value.split_whitespace().collect();
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn pinned_voprf_matches_rfc9497_vectors() {
    let public_key = Ristretto255::deserialize_elem(&hex(PK_SM)).unwrap();
    for vector in vectors() {
        let inputs: Vec<Vec<u8>> = vector.inputs.iter().map(|input| hex(input)).collect();
        let mut states = Vec::new();
        for ((input, blind), expected) in inputs.iter().zip(&vector.blinds).zip(&vector.blinded) {
            let blind = Ristretto255::deserialize_scalar(&hex(blind)).unwrap();
            let blinded =
                VoprfClient::<Ristretto255>::deterministic_blind_unchecked(input, blind).unwrap();
            assert_eq!(blinded.message.serialize().to_vec(), hex(expected));
            states.push(blinded.state);
        }

        let evaluated: Vec<EvaluationElement<Ristretto255>> = vector
            .evaluated
            .iter()
            .map(|element| EvaluationElement::deserialize(&hex(element)).unwrap())
            .collect();
        let proof = Proof::<Ristretto255>::deserialize(&hex(vector.proof)).unwrap();
        let inputs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
        let outputs: Vec<Vec<u8>> =
            VoprfClient::batch_finalize(&inputs, &states, &evaluated, &proof, public_key)
                .unwrap()
                .map(|output| output.unwrap().to_vec())
                .collect();
        let expected: Vec<Vec<u8>> = vector.outputs.iter().map(|output| hex(output)).collect();
        assert_eq!(outputs, expected);
    }
}
