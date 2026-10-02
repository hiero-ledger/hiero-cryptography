// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hcpq;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A strict reader for the JSON subset used by the vector files: objects, arrays, strings, integers, booleans and
 * null. Anything else, including fractions, exponents and trailing content, is rejected so a malformed vector file
 * fails loudly instead of being partially read.
 */
final class Json {
    private final String text;
    private int pos;

    private Json(final String text) {
        this.text = text;
    }

    static Object parse(final String text) {
        final var reader = new Json(text);
        final var value = reader.value();
        reader.whitespace();
        if (reader.pos != text.length()) {
            throw reader.error("trailing content");
        }
        return value;
    }

    private Object value() {
        whitespace();
        if (pos >= text.length()) {
            throw error("unexpected end of input");
        }
        final char c = text.charAt(pos);
        return switch (c) {
            case '{' -> object();
            case '[' -> array();
            case '"' -> string();
            case 't' -> literal("true", Boolean.TRUE);
            case 'f' -> literal("false", Boolean.FALSE);
            case 'n' -> literal("null", null);
            default -> {
                if (c == '-' || (c >= '0' && c <= '9')) {
                    yield integer();
                }
                throw error("unexpected character '" + c + "'");
            }
        };
    }

    private Map<String, Object> object() {
        final var result = new LinkedHashMap<String, Object>();
        expect('{');
        whitespace();
        if (peek('}')) {
            pos++;
            return result;
        }
        do {
            whitespace();
            final var key = string();
            whitespace();
            expect(':');
            if (result.put(key, value()) != null) {
                throw error("duplicate key \"" + key + "\"");
            }
            whitespace();
        } while (consume(','));
        expect('}');
        return result;
    }

    private List<Object> array() {
        final var result = new ArrayList<>();
        expect('[');
        whitespace();
        if (peek(']')) {
            pos++;
            return result;
        }
        do {
            result.add(value());
            whitespace();
        } while (consume(','));
        expect(']');
        return result;
    }

    private String string() {
        expect('"');
        final var sb = new StringBuilder();
        while (true) {
            if (pos >= text.length()) {
                throw error("unterminated string");
            }
            final char c = text.charAt(pos++);
            if (c == '"') {
                return sb.toString();
            }
            if (c < 0x20) {
                throw error("unescaped control character in string");
            }
            if (c != '\\') {
                sb.append(c);
                continue;
            }
            if (pos >= text.length()) {
                throw error("unterminated escape");
            }
            final char e = text.charAt(pos++);
            switch (e) {
                case '"', '\\', '/' -> sb.append(e);
                case 'b' -> sb.append('\b');
                case 'f' -> sb.append('\f');
                case 'n' -> sb.append('\n');
                case 'r' -> sb.append('\r');
                case 't' -> sb.append('\t');
                case 'u' -> {
                    if (pos + 4 > text.length()) {
                        throw error("truncated unicode escape");
                    }
                    sb.append((char) Integer.parseInt(text, pos, pos + 4, 16));
                    pos += 4;
                }
                default -> throw error("invalid escape '\\" + e + "'");
            }
        }
    }

    private Long integer() {
        final int start = pos;
        if (peek('-')) {
            pos++;
        }
        while (pos < text.length() && Character.isDigit(text.charAt(pos))) {
            pos++;
        }
        if (pos < text.length() && ".eE".indexOf(text.charAt(pos)) >= 0) {
            throw error("only integers are supported");
        }
        return Long.parseLong(text.substring(start, pos));
    }

    private Object literal(final String word, final Object value) {
        if (!text.startsWith(word, pos)) {
            throw error("expected " + word);
        }
        pos += word.length();
        return value;
    }

    private void whitespace() {
        while (pos < text.length() && " \t\r\n".indexOf(text.charAt(pos)) >= 0) {
            pos++;
        }
    }

    private boolean peek(final char c) {
        return pos < text.length() && text.charAt(pos) == c;
    }

    private boolean consume(final char c) {
        if (peek(c)) {
            pos++;
            return true;
        }
        return false;
    }

    private void expect(final char c) {
        if (!consume(c)) {
            throw error("expected '" + c + "'");
        }
    }

    private IllegalArgumentException error(final String message) {
        return new IllegalArgumentException(message + " at offset " + pos);
    }
}
