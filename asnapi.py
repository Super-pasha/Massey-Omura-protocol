import asn1


def rt_assert(expr):
    if not expr:
        raise Exception('Asn1 parse error')


def peek_and_enter(decoder, asn1_number):
    tag = decoder.peek()
    rt_assert(tag.typ == asn1.Types.Constructed)
    rt_assert(tag.nr == asn1_number)
    decoder.enter()


def peek_and_skip(decoder):
    tag = decoder.peek()
    rt_assert(tag.typ == asn1.Types.Primitive)
    decoder.read()


def peek_and_get(decoder, asn1_number):
    tag = decoder.peek()
    rt_assert(tag.typ == asn1.Types.Primitive)

    tag, value = decoder.read()
    rt_assert(tag.nr == asn1_number)
    return value


def leave(decoder):
    decoder.leave()


def export_client_msg1(prime, power, data):

    encoder = asn1.Encoder()
    encoder.start()
    encoder.enter(asn1.Numbers.Sequence)
    encoder.enter(asn1.Numbers.Set)
    encoder.enter(asn1.Numbers.Sequence)

    # identifiers of Massey-Omura protocol
    encoder.write('\x80\x07\x02\x00', asn1.Numbers.OctetString)
    encoder.write(b'mo', asn1.Numbers.UTF8String)

    # empty sequence
    encoder.enter(asn1.Numbers.Sequence)
    encoder.leave()

    # crypto system parameters: p, r
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(prime, asn1.Numbers.Integer)
    encoder.write(power, asn1.Numbers.Integer)
    encoder.leave()
    encoder.leave()

    # ciphertext
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(data, asn1.Numbers.Integer)
    encoder.leave()
    encoder.leave()
    encoder.leave()

    # empty sequence
    encoder.enter(asn1.Numbers.Sequence)
    encoder.leave()

    return encoder.output()


def import_client_msg1(asn1_blob):

    decoder = asn1.Decoder()
    decoder.start(asn1_blob)

    peek_and_enter(decoder, asn1.Numbers.Sequence)
    peek_and_enter(decoder, asn1.Numbers.Set)
    peek_and_enter(decoder, asn1.Numbers.Sequence)

    # identifiers
    peek_and_skip(decoder)
    peek_and_skip(decoder)

    # empty sequence
    peek_and_enter(decoder, asn1.Numbers.Sequence)
    leave(decoder)

    # crypto system parameters: p, r
    peek_and_enter(decoder, asn1.Numbers.Sequence)
    prime = peek_and_get(decoder, asn1.Numbers.Integer)
    power = peek_and_get(decoder, asn1.Numbers.Integer)
    leave(decoder)
    leave(decoder)

    # ciphertext
    peek_and_enter(decoder, asn1.Numbers.Sequence)
    data = peek_and_get(decoder, asn1.Numbers.Integer)
    leave(decoder)
    leave(decoder)
    leave(decoder)

    # empty sequence
    peek_and_enter(decoder, asn1.Numbers.Sequence)
    leave(decoder)

    return {
        'power': power,
        'prime': prime,
        'data': data,
    }

def export_server_msg1(data):
    
    encoder = asn1.Encoder()
    encoder.start()
    encoder.enter(asn1.Numbers.Sequence)
    encoder.enter(asn1.Numbers.Set)
    encoder.enter(asn1.Numbers.Sequence)

    # identifiers of Massey-Omura protocol
    encoder.write('\x80\x07\x02\x00', asn1.Numbers.OctetString)
    encoder.write(b'mo', asn1.Numbers.UTF8String)

    # empty sequence
    encoder.enter(asn1.Numbers.Sequence)
    encoder.leave()

    # crypto system parameters: none
    encoder.enter(asn1.Numbers.Sequence)
    encoder.leave()

    # ciphertext
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(data, asn1.Numbers.Integer)
    encoder.leave()
    encoder.leave()
    encoder.leave()

    # empty sequence
    encoder.enter(asn1.Numbers.Sequence)
    encoder.leave()
    encoder.leave()

    return encoder.output()

    

def import_server_msg1(asn1_blob):
    
    decoder = asn1.Decoder()
    decoder.start(asn1_blob)
    peek_and_enter(decoder, asn1.Numbers.Sequence)
    peek_and_enter(decoder, asn1.Numbers.Set)
    peek_and_enter(decoder, asn1.Numbers.Sequence)

    # identifiers
    peek_and_skip(decoder)
    peek_and_skip(decoder)

    # empty sequence
    peek_and_enter(decoder, asn1.Numbers.Sequence)
    leave(decoder)

    # crypto system parameters: none
    peek_and_enter(decoder, asn1.Numbers.Sequence)
    leave(decoder)

    # ciphertext
    peek_and_enter(decoder, asn1.Numbers.Sequence)
    data = peek_and_get(decoder, asn1.Numbers.Integer)
    leave(decoder)
    leave(decoder)
    leave(decoder)

    # empty sequence
    peek_and_enter(decoder, asn1.Numbers.Sequence)
    leave(decoder)
    leave(decoder)

    return {
        'data': data,
    }


def export_client_msg2(data, length, name):

    encoder = asn1.Encoder()
    encoder.start()
    encoder.enter(asn1.Numbers.Sequence)
    encoder.enter(asn1.Numbers.Set)
    encoder.enter(asn1.Numbers.Sequence)

    # identifiers of Massey-Omura protocol
    encoder.write('\x80\x07\x02\x00', asn1.Numbers.OctetString)
    encoder.write(b'mo', asn1.Numbers.UTF8String)

    # empty sequence
    encoder.enter(asn1.Numbers.Sequence)
    encoder.leave()

    # crypto system parameters: none
    encoder.enter(asn1.Numbers.Sequence)
    encoder.leave()

    # ciphertext
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(data, asn1.Numbers.Integer)
    encoder.leave()
    encoder.leave()
    encoder.leave()

    # encrypted message
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write('\x01\x21', asn1.Numbers.OctetString)
    encoder.write(length, asn1.Numbers.Integer)
    encoder.write(name, asn1.Numbers.OctetString)
    encoder.leave()
    encoder.leave()

    return encoder.output()


def import_client_msg2(asn1_blob):

    decoder = asn1.Decoder()
    decoder.start(asn1_blob)
    peek_and_enter(decoder, asn1.Numbers.Sequence)
    peek_and_enter(decoder, asn1.Numbers.Set)
    peek_and_enter(decoder, asn1.Numbers.Sequence)

    # identifiers
    peek_and_skip(decoder)
    peek_and_skip(decoder)

    # empty sequence
    peek_and_enter(decoder, asn1.Numbers.Sequence)
    leave(decoder)

    # crypto system parameters: p, r
    peek_and_enter(decoder, asn1.Numbers.Sequence)
    leave(decoder)

    # ciphertext
    peek_and_enter(decoder, asn1.Numbers.Sequence)
    data = peek_and_get(decoder, asn1.Numbers.Integer)
    leave(decoder)
    leave(decoder)
    leave(decoder)

    # encrypted message
    peek_and_enter(decoder, asn1.Numbers.Sequence)
    peek_and_skip(decoder)
    length = peek_and_get(decoder, asn1.Numbers.Integer)
    name = peek_and_get(decoder, asn1.Numbers.OctetString)
    leave(decoder)
    leave(decoder)

    return {
        'data': data,
        'length': length,
        'name' : name
    }