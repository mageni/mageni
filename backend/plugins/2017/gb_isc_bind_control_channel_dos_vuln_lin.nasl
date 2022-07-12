##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_isc_bind_control_channel_dos_vuln_lin.nasl 13654 2019-02-14 07:51:59Z mmartin $
#
# ISC BIND Control Channel Denial of Service Vulnerability (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810977");
  script_version("$Revision: 13654 $");
  script_cve_id("CVE-2017-3138");
  script_bugtraq_id(97657);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 08:51:59 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-05-23 11:40:43 +0530 (Tue, 23 May 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ISC BIND Control Channel Denial of Service Vulnerability (Linux)");

  script_tag(name:"summary", value:"The host is installed with ISC BIND and is
  prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a feature in named
  which allows operators to issue commands to a running server by communicating
  with the server process over a control channel, using a utility program such
  as rndc.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (assertion failure and daemon exit) via
  null command string.");

  script_tag(name:"affected", value:"ISC BIND 9.9.9 through 9.9.9-P7, 9.9.10b1
  through 9.9.10rc2, 9.10.4 through 9.10.4-P7, 9.10.5b1 through 9.10.5rc2,
  9.11.0 through 9.11.0-P4, 9.11.1b1 through 9.11.1rc2, 9.9.9-S1 through
  9.9.9-S9 on Linux.");

  script_tag(name:"solution", value:"Upgrade to ISC BIND version 9.9.9-P8 or
  9.10.4-P8 or 9.11.0-P5 or 9.9.9-S10 or 9.9.10rc3 or 9.10.5rc3 or 9.11.1rc3
  or later on Linux.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01471/74/CVE-2017-3138");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("bind_version.nasl", "os_detection.nasl");
  script_mandatory_keys("ISC BIND/installed", "Host/runs_unixoide");
  script_xref(name:"URL", value:"https://www.isc.org");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("revisions-lib.inc");

if( ! bindPort = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:bindPort ) ) exit( 0 );

bindVer = infos["version"];
proto = infos["proto"];

if(bindVer =~ "^(9\.9)")
{
  if (bindVer =~ "9\.9\.9" && revcomp(a: bindVer, b: "9.9.9.P8") < 0){
      fix = "9.9.9-P8";
    }

  else if((revcomp(a: bindVer, b: "9.9.10.b1") >= 0) && (revcomp(a: bindVer, b: "9.9.10.rc3") < 0)){
    fix = "9.9.10.rc3";
  }

  else if((revcomp(a: bindVer, b: "9.10.4") >= 0) && (revcomp(a: bindVer, b: "9.10.4.P8") < 0)){
    fix = "9.10.4.P8";
  }

  else if((revcomp(a: bindVer, b: "9.10.5.b1") >= 0) && (revcomp(a: bindVer, b: "9.10.5.rc3") < 0)){
    fix = "9.10.5.rc3";
  }

  else if((revcomp(a: bindVer, b: "9.11.0") >= 0) && (revcomp(a: bindVer, b: "9.11.0.P5") < 0)){
    fix = "9.11.0.P5";
  }

  else if((revcomp(a: bindVer, b: "9.11.1.b1") >= 0) && (revcomp(a: bindVer, b: "9.11.1.rc3") < 0)){
    fix = "9.10.5.rc3";
  }

  else if((revcomp(a: bindVer, b: "9.9.9.S1") >= 0) && (revcomp(a: bindVer, b: "9.9.9.S10") < 0)){
    fix = "9.9.9.S10";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:bindVer, fixed_version:fix);
  security_message(data:report, port:bindPort, proto:proto);
  exit(0);
}

exit(99);
