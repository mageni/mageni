# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Important note: In all functions only "http_send_recv()" has been used as
# "http_keepalive_send_recv()" might not fully work against embedded devices like printers.

global_var ipp_tags_map;

global_var IPP_TAG_MAP_KEY, IPP_ATTRIBUTE_MAP_KEY, IPP_VALUE_MAP_KEY, IPP_OFFSET_MAP_KEY;

IPP_TAG_MAP_KEY =       "tag";
IPP_ATTRIBUTE_MAP_KEY = "attribute";
IPP_VALUE_MAP_KEY =     "value";
IPP_OFFSET_MAP_KEY =    "offset";

ipp_tags_map = make_array( 0x45, "printer-uri",
                           0x47, "attributes-charset",
                           0x48, "attributes-natural-language" );

# @brief Decodes an attribute-value pair from the given IPP response, starting at the given offset.
#
# @param r - the IPP response string
# @param offset - the position in the IPP where to start reading
#
# @return Returns an array containing key-value mappins relevant to the current attribute, or NULL if something went wrong
#
function ipp_decode_attribute( r, offset ) {
  local_var r, offset;
  local_var tag, answer, attr_len, attr, val_len, value, r_length, has_more_values, tmp_value, value_tp;

  if ( isnull( offset ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#offset#-#ipp_decode_attribute" );
    return;
  }

  if ( ! r ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#r#-#ipp_decode_attribute" );
    return;
  }

  # nb: Attribute format is <tag><2 bytes attribute name length><attribute name><2 bytes value length><value>
  r_length = strlen( r );
  answer = make_array();
  tag = r[offset++];
  answer[IPP_TAG_MAP_KEY] = tag;

  attr_len = getword( blob:r, pos:offset );
  if ( offset + attr_len > r_length )
    return NULL;

  offset += 2;
  attr = substr( r, offset, offset + attr_len - 1 );
  if ( ! attr )
    return NULL;

  offset += attr_len;

  answer[IPP_ATTRIBUTE_MAP_KEY] = attr;
  has_more_values = FALSE;
  value = "";
  # nb: Each attribute can have multiple values.
  # Starting with the second value, the format is <tag><2 zero bytes><length><value>
  repeat {
    val_len = getword( blob:r, pos:offset );
    offset += 2;
    has_more_values = FALSE;
    tag_nr = ord( tag );

    if ( ( ord( tag ) == 0x21 ) || ( ord( tag ) == 0x23 ) ) { # integer or enum type
      tmp_value = getdword( blob:r, pos:offset );
      offset += 4;

    } else if ( ord( tag ) == 0x22 ) { # boolean type
      tmp_value = ord( r[offset] );
      offset++;

    } else if ( ord( tag) == 0x33 ) { # range of integer type
      value1 = getdword( blob:r, pos:offset );
      offset += 4;
      value2 = getdword( blob:r, pos:offset );
      offset += 4;
      tmp_value = value1 + "-" + value2;

    } else if ( ord( tag) == 0x32 ) { # resolution type
      tmp_value = getdword( blob:r, pos:offset );
      tmp_value += "X";
      offset += 4;
      tmp_value += getdword( blob:r, pos:offset );
      offset += 4;
      value_tp = ord( r[offset++] );

      if ( value_tp == 0x03 )
        tmp_value += "dpi";
      else
        tmp_value += "dpcm";

    } else if ( ord( tag ) == 0x31 ) { # date type; maybe formatting can be improved
      tmp_value = getword( blob:r, pos:offset );
      offset += 2;

      tmp_value += "-" + ord( r[offset++] );
      tmp_value += "-" + ord( r[offset++] );
      tmp_value += "T" + ord( r[offset++] );
      tmp_value += ":" + ord( r[offset++] );
      tmp_value += ":" + ord( r[offset++] );
      tmp_value += "." + ord( r[offset++] );
      tmp_value += r[offset++]; # should be +
      tmp_value += getword( blob:r, pos:offset );
      offset += 2;

    } else if ( ( ord( tag ) == 0x35 ) || ( ord( tag ) == 0x36 ) ) { # text or name with language
      val_len = getword( blob:r, pos:offset );
      offset += 2;
      tmp_value = substr( r, offset, offset + val_len - 1 );
      offset += val_len;
      val_len = getword( blob:r, pos:offset );
      offset += 2;
      tmp_value += " " + substr( r, offset, offset + val_len - 1 );
      offset += val_len;

    } else { # all other types
      tmp_value = "";
      if ( val_len > 0 ) {
        tmp_value = substr( r, offset, offset + val_len - 1 );
        offset += val_len;
      }
    }

    crt = ord( r[offset] );

    # nb: This is the check for multiple values. In some cases there is a \r\n before the end tag (0x03) so taking that into account
    if ( crt != 0x4A && crt != 0x37 && crt != 0x03 && crt != 0x04 && ! ( crt == 0x0D && ord( r[offset + 1] ) == 0x0A ) &&
         ord( r[offset + 1] ) == 0x00 && ord( r[offset + 2] ) == 0x00 && offset < r_length ) {
      has_more_values = TRUE;
      tag = r[offset];
      offset += 3; # nb: Skip tag and the two 0s
    }

    if ( value )
      value += ", " + tmp_value;
    else
      value = tmp_value;
  } until( ! has_more_values );

  # nb: Answer array needs to contain the attribute name, the value(es) and the offset from where to read further
  answer[IPP_VALUE_MAP_KEY] = value;
  answer[IPP_OFFSET_MAP_KEY] = offset;

  return answer;
}

# @brief Encodes an attribute based on tag and value. Since we only send some standard attributes,
#        they are mapped as tag to attribute name in an global array.
#
# @param attribute_tag - the IPP attribute tag, that should have an entry in the ipp_tags_map array
# @param attribute_value - the value to be encoded for the current tag
#
# @return Returns a raw_string containing the encoded attribute and value
#
function ipp_encode_attribute( attribute_tag, attribute_value ) {

  local_var attribute_tag, attribute_value;
  local_var _attr_data, attr, attr_len, val_len;

  if ( ! attribute_tag ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#attribute_tag#-#ipp_encode_attribute" );
    return;
  }

  if ( isnull( attribute_value ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#attribute_value#-#ipp_encode_attribute" );
    return;
  }

  _attr_data = raw_string( attribute_tag );

  attr = ipp_tags_map[attribute_tag];

  if ( ! attr )
    return;

  attr_len = strlen( attr );
  _attr_data += raw_string( mkword( attr_len ) );
  _attr_data += attr;

  val_len = strlen( attribute_value );
  _attr_data += raw_string( mkword( val_len ) );
  _attr_data += attribute_value;

  return _attr_data;
}

# @brief Creates an IPP request with the given attributes.
#
# @param host - the target host
# @param port - the target port
# @param url - the url to be used in the HTTP / IPP part of the request
# @param ipp_version - the desired IPP version, as raw_string
# @param operation - the desired operation, as raw_string
# @param requested_attributes - an optional list containing the desired attributes to be retrieved.
#                               This is not needed when requesting CUPS-Get-Devices operation.
# @param send_printer_uri - when set to TRUE, the printer-uri attribute is added to the operation-attributes-tag
#
# @return Returns a valid IPP request, or NULL if something went wrong
#
function ipp_prepare_request( host, port, url, ipp_version, operation, requested_attributes, send_printer_uri ) {

  local_var host, port, url, ipp_version, operation, requested_attributes, send_printer_uri;
  local_var data, attr, attr_len, val, attr_data, req, header, request_id, i;

  if ( ! host ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#host#-#ipp_prepare_request" );
    return;
  }

  if ( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#ipp_prepare_request" );
    return;
  }

  if ( ! url ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#url#-#ipp_prepare_request" );
    return;
  }

  if ( ! operation ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#operation#-#ipp_prepare_request" );
    return;
  }

  request_id = rand() % 65536;
  if ( isnull( ipp_version ) )
    ipp_version = raw_string( 0x01, 0x01 ); # nb: After testing, it seems that newer printers still support 1.1, but older ones do not support 2.0

  data = ipp_version +            # IPP Version
         operation  +             # Operation ID
         mkdword( request_id ) +  # Request ID
         raw_string( 0x01 );      # operation-attributes-tag

  # nb: It seems these 2 attributes are mandatory and always needed at the beginning
  attr_data = ipp_encode_attribute( attribute_tag:0x47, attribute_value:"utf-8" );

  if ( ! attr_data )
    return NULL; # nb: These attributes are mandatory, we cannot continue without

  data += attr_data;
  attr_data = ipp_encode_attribute( attribute_tag:0x48, attribute_value:"en-us" );

  if ( ! attr_data )
    return NULL; # nb: These attributes are mandatory, we cannot continue without

  data += attr_data;
  if ( send_printer_uri ) {
    # eg. ipp://<ip>:631/ipp/print
    val = "ipp://" + host + url;
    attr_data = ipp_encode_attribute( attribute_tag:0x45, attribute_value:val );

    if ( ! attr_data )
      return NULL; # nb: These attributes are mandatory, we cannot continue without

    data += attr_data;
  }

  if ( ! isnull( requested_attributes ) ) {
    data += raw_string( 0x44 ); # keyword tag
    attr = "requested-attributes";
    attr_len = strlen( attr );
    data += raw_string( mkword( attr_len ) );
    data += attr;
    i = 0;

    foreach attr( requested_attributes ) {
      if ( i > 0 ) { # nb: Only add the tag if it is not the first value
        data += raw_string( 0x44 ); # keyword tag
        attr_len = strlen( attr );
        data += raw_string( mkdword( attr_len ) );
        data += attr;
      } else {
        attr_len = strlen( attr );
        data += raw_string( mkword( attr_len ) );
        data += attr;
      }
      i++;
    }
  }

  data += raw_string( 0x03 ); # end-of-attributes tag

  header = make_array( "Content-Type", "application/ipp",
                       "Expect", "100-continue" );

  req = http_post_put_req( port:port, url:url, data:data, add_headers:header, host_header_use_ip:TRUE );
  return req;
}

# @brief Sends the IPP requests and tries to get and parse the reply.
#
# @param port - the target port
# @param req - the IPP request to be send
#
# @return Returns an array with the attribute name and value pairs obtained from the IPP reply, or NULL
#
function ipp_get_and_parse_reply( port, req ) {

  local_var port, req;
  local_var res, body, chunked, idx, body_length, offset, request_id, tag, answers, vals, tmp_vals;

  if ( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#ipp_get_and_parse_reply" );
    return;
  }

  if ( ! req ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#req#-#ipp_get_and_parse_reply" );
    return;
  }

  res = http_send_recv( port:port, data:req );

  if ( ! res )
    return NULL;
  # eg HTTP/1.1 100 Continue
  #
  #
  # HTTP/1.1 200 OK
  # MIME-Version: 1.0
  # Transfer-Encoding: chunked
  # Connection: Keep-Alive
  # Keep-Alive: timeout=30
  # Content-Type: application/ipp
  #
  # 12e
  if ( res =~ "^HTTP/(1\.[01]|2) 100" ) {
    res = http_extract_body_from_response( data:res );
     # nb: After continue there is an extra space we need to remove
    if (res =~ '^\r\n' ) {
      res = substr( res, 2, strlen( res ) );
    }
  }

  if ( res !~ "^HTTP/(1\.[01]|2) 200" )
    return NULL;

  chunked = FALSE;
  if( egrep( pattern:"^Transfer-Encoding\s*:\s*chunked", string:res, icase:TRUE ) )
    chunked = TRUE;

  body = http_extract_body_from_response( data:res );

  while ( body =~ '^\r\n' ) { # nb: chomp() would not work in this case
    body_length = strlen( body );
    body = substr( body, 2, body_length );
  }

  if ( ! body )
    return NULL;

  if ( chunked ) {
    idx = stridx( body, '\r\n' );
    if ( idx > 0 ) {
      body = substr( body, idx + 2, strlen( body ) - 1 );
    }
  }

  body_length = strlen( body );
  # Nb: Jumping 2 bytes for version and 2 for status
  offset = 4;

  if ( ord( body[ 2 ] ) != 0 || ord( body[ 3 ] ) != 0 )
    return NULL; # status code is not successful

  request_id = substr( body, 4, 4 );
  offset = 8;
  tag = body[offset++];

  if ( ord( tag ) != 0x01 )
    return NULL; # We expect operation-attributes-tag

  # nb: Operation attributes are not interesting for now and can be ignored
  while ( ord( body[offset] ) != 0x04 && offset < body_length ) {
    answers = ipp_decode_attribute( r:body, offset:offset );

    if ( isnull( answers ) )
      return NULL;

    offset = answers["offset"];
  }

  vals = make_array();
  tmp_vals = make_array();
  idx = 1;

  # nb: Reading the requested attributes
  while ( ord( body[offset] ) == 0x04 && offset < body_length ) {
    offset++;
    while ( offset < body_length && ord( body[offset] ) != 0x03 && ord( body[offset] ) != 0x04 &&
      ! ( ord( body[offset] ) == 0x0d && ord( body[offset] ) == 0x0a ) ) {
      answers = ipp_decode_attribute( r:body, offset:offset );
      if ( isnull( answers ) )
        offset = body_length; # nb: We force a break here, as this happens when eg. reaching \r\n but we are not at end of the body
      else {
        offset = answers["offset"];
        tmp_vals[answers[IPP_ATTRIBUTE_MAP_KEY]] = answers[IPP_VALUE_MAP_KEY];
      }
    }
    printer_name = tmp_vals["printer-name"];
    if ( ! printer_name ) {
      printer_name = "printer" + idx;
      idx = idx + 1;
    }
    vals[printer_name] = tmp_vals;
  }
  return vals;
}

# @brief Creates an IPP request to read the printer model and version, and parses the reply.
#
# @param port - the target port
# @param url - the URL where the IPP request will be sent
#
# @return Returns an array with the attribute name and value pairs obtained from the IPP reply, or NULL
#
function ipp_get_printer_model_version_info( port, url ) {

  local_var port, url;
  local_var operation_id, host, req_attrs, req, vals, body;
  local_var body_length, tag, answers;

  if ( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#ipp_get_printer_model_version_info" );
    return;
  }

  if ( ! url ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#url#-#ipp_get_printer_model_version_info" );
    return;
  }

  host = get_host_ip( port:port );
  req_attrs = make_list( "printer-name",
                         "printer-info",
                         "printer-make-and-model",
                         "printer-firmware-name",
                         "printer-firmware-string-version",
                         "printer-firmware-patches",
                         "printer-firmware-version" );

  operation_id = raw_string( 0x00, 0x0b ); # Operation-ID, Get-Printer-Attributes
  req = ipp_prepare_request( host:host, port:port, url:url, operation:operation_id, requested_attributes:req_attrs, send_printer_uri:TRUE );

  if ( ! req )
    return NULL;

  vals = ipp_get_and_parse_reply( port:port, req:req );

  return vals;
}

# @brief Creates an IPP request for the CUPS-Get-Printers operation.
# @note It was noticed that some newer models do not support this operation.
#
# @param port - the target port
#
# @return Returns an array with the attribute name and value pairs obtained from the IPP reply, or NULL
#
function ipp_cups_get_printers( port ) {

  local_var port;
  local_var ipp_version, operation_id, host, req, body, offset, body_length, uris, vals, answers, device_uri, tmp_vals;

  if ( ! port ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#ipp_cups_get_printers" );
    return;
  }

  ipp_version = raw_string( 0x01, 0x01 ); # nb: ipptool always used version 1.1 for CUPS-Get-Printers
  operation_id = raw_string( 0x40, 0x02 ); # Operation-ID, CUPS-Get-Printers

  host = get_host_ip( port:port );

  req = ipp_prepare_request( host:host, port:port, url:"/", ipp_version:ipp_version, operation:operation_id );

  if ( ! req )
    return NULL;

  vals = ipp_get_and_parse_reply( port:port, req:req );

  if ( ! vals )
    return NULL;

  return vals;
}
# @brief Generic function to get the list of attributes from a printer via IPP. This acts as a wrapper for operation-specific functions.
#
# @param port - the target port
#
# @return Returns an array with the attribute name and value pairs obtained from the IPP reply, or NULL
#
function ipp_get_printer_info( port ) {

  local_var port;
  local_var attributes, extra;

  if ( isnull( port ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#ipp_get_printer_info" );
    return NULL;
  }

  attributes = ipp_cups_get_printers( port:port );
  extra = make_array();

  if ( isnull( attributes ) || ! is_array( attributes ) ) {
    # nb: Some devices (e.g. HP OfficeJet 8600 Pro) are responding only on specific URLs
    foreach url( make_list( "/", "/ipp/printers", "/ipp/print" ) ) {
      attributes = ipp_get_printer_model_version_info( port:port, url:url );
      if ( ! isnull( attributes ) && is_array( attributes ) ) {
        extra["extra-used-method"] = "Get-Printer-Attributes";
        extra["extra-extracted-url"] = http_report_vuln_url( port:port, url:url, url_only:TRUE );
        break;
      }
    }
  } else {
    extra["extra-used-method"] = "CUPS-Get-Printers";
  }

  if ( ! isnull( attributes ) ) {
    service_register( port:port, proto:"ipp" );
    # nb: Could be an empty array so using "is_array()" instead of "if( extra )"
    if ( is_array( extra ) )
      attributes["Extra information"] = extra;
  }

  return attributes;
}
