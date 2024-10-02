import assert from 'node:assert';
import { readFile } from 'node:fs/promises';
import { describe, it } from 'node:test';
import { parse } from 'tldts';
import { getEmptyResult, IOptions, IResult, parseImpl } from 'tldts-core';
import suffixLookup from 'tldts/src/suffix-trie';
import parsePSL, { IRule } from '../src/tldts-utils/parser';

const parseWithRules = (hostname: string, parseOptions: Partial<IOptions> & { extraRules?: IRule[] }): IResult => {
    return parseImpl(hostname, 5, (hostname, options, out) => {
        for (const rule of parseOptions.extraRules || []) {
            if (hostname.endsWith('.' + rule.rule)) {
                out.isIcann = false;
                out.isPrivate = true;
                out.publicSuffix = rule.rule;
                return;
            }
        }

        return suffixLookup(hostname, options, out);
    }, parseOptions, getEmptyResult());
}

describe("Uniqueness Test", () => {
    it("should not contain entries which are already on the PSL", async () => {
        const rules: IRule[] = [];
        parsePSL(await readFile("public_suffix_list.dat", { encoding: 'utf-8' }), rule => {
            rules.push(rule);
        });

        for (const rule of rules) {
            const result = parse(rule.rule, { allowPrivateDomains: true });
            assert.equal(result.isIcann, true, rule.rule);
            assert.equal(result.isPrivate, false, rule.rule);
            assert.notEqual(result.domain, null, rule.rule);

            const resultWithRules = parseWithRules(`test.${rule.rule}`, { allowPrivateDomains: true, extraRules: rules });
            assert.equal(resultWithRules.isIcann, false, rule.rule);
            assert.equal(resultWithRules.isPrivate, true, rule.rule);
            assert.equal(resultWithRules.publicSuffix, rule.rule, rule.rule);
        }
    })
})
