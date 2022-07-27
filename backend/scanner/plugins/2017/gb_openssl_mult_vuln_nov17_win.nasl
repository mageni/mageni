###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_mult_vuln_nov17_win.nasl 13898 2019-02-27 08:37:43Z cfischer $
#
# OpenSSL Multiple Vulnerabilities - Nov 2017 (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107204");
  script_version("$Revision: 13898 $");
  script_cve_id("CVE-2017-3735", "CVE-2017-3736");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 09:37:43 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-11-03 09:50:03 +0100 (Fri, 03 Nov 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("OpenSSL Multiple Vulnerabilities - Nov 2017 (Windows)");

  script_tag(name:"summary", value:"This host is running OpenSSL and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A carry propagating bug in the x86_64 Montgomery squaring procedure.

  - Malformed X.509 IPAddressFamily which could cause OOB read.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to recover keys
  (private or secret keys) or to cause a buffer overread which lead to erroneous display of the certificate in text format.");

  script_tag(name:"affected", value:"OpenSSL 1.1.0 before 1.1.0g and 1.0.2 before 1.0.2m");

  script_tag(name:"solution", value:"Upgrade to OpenSSL version 1.1.0g or 1.0.2m or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20171102.txt");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(vers =~ "^1\.1\.0")
{
  if (version_is_less(version:vers, test_version:'1.1.0g'))
  {
    Vuln = TRUE;
    fix = '1.1.0g';
  }
}

else if(vers =~ "^1\.0\.2")
{
  if (version_is_less(version:vers, test_version:'1.0.2m'))
  {
    Vuln = TRUE;
    fix = '1.0.2m';
  }
}

if (Vuln)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);