# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:router_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170499");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-19 08:33:05 +0000 (Mon, 19 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-12 14:15:00 +0000 (Wed, 12 May 2021)");

  script_cve_id("CVE-2020-27649", "CVE-2020-27651", "CVE-2020-27653", "CVE-2020-27654",
                "CVE-2020-27655", "CVE-2020-27657", "CVE-2020-27658");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology Router Manager 1.2.x Multiple Vulnerabilities (Synology-SA-20:14)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_synology_srm_consolidation.nasl");
  script_mandatory_keys("synology/srm/detected");

  script_tag(name:"summary", value:"Synology Router Manager (SRM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-27649: An improper certificate validation vulnerability in OpenVPN client allows
  man-in-the-middle attackers to spoof servers and obtain sensitive information via a crafted
  certificate.

  - CVE-2020-27651: SRM does not set the Secure flag for the session cookie in an HTTPS session, which
  makes it easier for remote attackers to capture this cookie by intercepting its transmission within
  an HTTP session.

  - CVE-2020-27653: An algorithm downgrade vulnerability in QuickConnect allows man-in-the-middle
  attackers to spoof servers and obtain sensitive information via unspecified vectors.

  - CVE-2020-27654: An improper access control vulnerability in lbd allows remote attackers to
  execute arbitrary commands via port (1) 7786/tcp or (2) 7787/tcp.

  - CVE-2020-27655: An improper access control vulnerability allows remote attackers to access
  restricted resources via inbound QuickConnect traffic.

  - CVE-2020-27657: A cleartext transmission of sensitive information vulnerability in DDNS allows
  man-in-the-middle attackers to eavesdrop authentication information of DNSExit via unspecified
  vectors.

  - CVE-2020-27658: SRM does not include the HTTPOnly flag in a Set-Cookie header for the session
  cookie, which makes it easier for remote attackers to obtain potentially sensitive information via
  script access to this cookie.");

  script_tag(name:"affected", value:"Synology Router Manager version 1.2.x prior to 1.2.4-8081.");

  script_tag(name:"solution", value:"Update to firmware version 1.2.4-8081 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_20_14");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if ( ( version =~ "^1\.2" ) && ( revcomp( a:version, b:"1.2.4-8081" ) < 0 ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.2.4-8081" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
