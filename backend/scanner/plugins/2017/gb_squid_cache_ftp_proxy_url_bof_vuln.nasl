###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_squid_cache_ftp_proxy_url_bof_vuln.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# Squid Cache FTP Proxy URL Buffer Overflow Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:squid-cache:squid';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811542");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2002-0068");
  script_bugtraq_id(4148);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-28 12:44:20 +0530 (Fri, 28 Jul 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Squid Cache FTP Proxy URL Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"This host is running Squid and is prone
  to buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a buffer overflow error
  in the Squid proxy server's FTP URL handling.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to crash the squid process or execute arbitrary code. To exploit
  this vulnerability, and attacker must have the ability to use the Squid
  cache, and additionally be able to proxy FTP requests through the server.");

  script_tag(name:"affected", value:"Squid 2.0 through 2.4 STABLE3.");

  script_tag(name:"solution", value:"Upgrade to Squid version 2.4 STABLE4
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.squid-cache.org/Versions/v2/2.4/bugs");
  script_xref(name:"URL", value:"https://www.symantec.com/security_response/attacksignatures/detail.jsp?asid=24823");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_squid_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("squid_proxy_server/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 3128, 8080);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if (!sqport = get_app_port(cpe: CPE)){
  exit(0);
}

if (!version = get_app_version(cpe: CPE, port: sqport)){
  exit(0);
}

if (version =~ "2\.")
{
  if(revcomp(a: version, b: "2.4.STABLE4") < 0)
  {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.4.STABLE4");
    security_message(port: sqport, data: report);
    exit(0);
  }
}
exit(0);
