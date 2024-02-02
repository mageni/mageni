# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102092");
  script_version("2024-01-29T05:05:18+0000");
  script_tag(name:"last_modification", value:"2024-01-29 05:05:18 +0000 (Mon, 29 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-09 10:20:29 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2015-0204");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("DTLS: Deprecated DTLSv1.0 Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SSL and TLS");
  script_dependencies("gb_dtls_detect.nasl");
  script_mandatory_keys("dtls/detected");

  script_tag(name:"summary", value:"It was possible to detect the usage of the deprecated DTLSv1.0
  protocol on this system.");

  script_tag(name:"vuldetect", value:"Check the used DTLS protocols of the services provided by this
  system.");

  script_tag(name:"insight", value:"The DTLSv1.0 protocol contains known cryptographic
  flaws like:

  - CVE-2015-0204: Factoring Attack on RSA-EXPORT Keys Padding Oracle On Downgraded Legacy
  Encryption (FREAK)

  Note: Unlike for TLS there was now DTLSv1.1 protocol version and thus this VT isn't testing for
  this version.");

  script_tag(name:"impact", value:"An attacker might be able to use the known cryptographic flaws
  to eavesdrop the connection between clients and the service to get access to sensitive data
  transferred within the secured connection.

  Furthermore newly uncovered vulnerabilities in this protocols won't receive security updates
  anymore.");

  script_tag(name:"affected", value:"All services providing an encrypted communication using the
  DTLSv1.0 protocol.");

  script_tag(name:"solution", value:"It is recommended to disable the deprecated DTLSv1.0
  protocol in favor of the DTLSv1.2+ protocols. Please see the references for more
  information.");

  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc8996");
  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc7457");

  exit(0);
}

include("dtls_func.inc");
include("port_service_func.inc");
include("host_details.inc");

if( ! port = service_get_port( nodefault:TRUE, ipproto:"udp", proto:"dtls" ) )
  exit( 0 );

if ( ! supported = get_kb_item( "dtls/" + port + "/supported" ) )
  exit( 0 );

if( "DTLSv1.0" >< supported ) {

  # Store link between this and gb_dtls_detect.nasl
  # nb: We don't use the host_details.inc functions in both so we need to call this directly.
  register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.145817" ); # gb_dtls_detect.nasl
  register_host_detail( name:"detected_at", value:port + "/udp" );

  security_message( port:port, data:"The service is providing the deprecated DTLSv1.0 protocol.", proto:"udp" );
  exit( 0 );
}

exit( 99 );
