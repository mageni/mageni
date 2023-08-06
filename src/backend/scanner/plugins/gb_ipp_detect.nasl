# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170505");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-06-22 11:38:11 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Internet Printing Protocol (IPP) Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2023 Greenbone AG");
  # nb: Those are setting the "Host/could_support_ipp" so that we don't run this VT against every
  # web server and just against the ones on systems which *might* support IPP.
  script_dependencies("gb_get_http_banner.nasl", "dont_print_on_printers.nasl", "gb_pcl_pjl_detect.nasl");
  script_require_ports("Services/www", 631);
  script_mandatory_keys("Host/could_support_ipp");

  script_xref(name:"URL", value:"https://www.rfc-editor.org/rfc/rfc8011");
  script_xref(name:"URL", value:"https://www.pwg.org/ipp/");

  script_tag(name:"summary", value:"Detection of services supporting the Internet Printing Protocol
  (IPP).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

# nb: Unlike other printer related VTs we're not setting the host as "Host/dead" here because IPP
# is also e.g. provided / supported by CUPS which can be running on any arbitrary system.

include("host_details.inc");
include("byte_func.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("ipp.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:631 );

attributes = ipp_get_printer_info( port:port );
if ( isnull( attributes ) || ! is_array( attributes ) )
  exit( 0 );

found = FALSE;
extra = "";

foreach printer( keys( attributes ) ) {

  # nb: Will be handles separately later...
  if ( printer == "Extra information" )
    continue;

  values = attributes[printer];
  extra += '\t' + printer + ':\n';
  set_kb_item( name:"ipp/" + port + "/printer", value:printer );
  foreach key( keys( values ) ) {
    if ( key =~ "^printer" ) {
      val = values[key];
      if ( val ) {
        set_kb_item( name:"ipp/" + port + "/" + printer + "/" + key, value:val );
        extra += '\t\t' + key + " : " + val + '\n';
        found = TRUE;
      }
    }
  }
}

# nb: Just some extra information for the reporting.
foreach printer( keys( attributes ) ) {

  if ( printer != "Extra information" )
    continue;

  values = attributes[printer];
  extra += '\n' + printer + ':\n';
  foreach key( keys( values ) ) {
    if ( key =~ "^extra" ) {
      val = values[key];
      # nb: We're currently not saving this info into the KB but still could do that if required
      if ( val )
        extra += '\t' + key + " : " + val + '\n';
    }
  }
}

if ( found ) {
  set_kb_item( name:"ipp/port", value:port );
  report = "The remote host supports the Internet Printing Protocol (IPP) on port " + port + '/tcp.\n\n';
  report += 'Extracted attributes related to a printer:\n';
  report += extra;

  log_message( port:port, data:chomp( report ) );
}

exit( 0 );