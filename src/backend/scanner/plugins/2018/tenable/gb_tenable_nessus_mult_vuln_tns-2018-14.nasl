###############################################################################
# OpenVAS Vulnerability Test
#
# Tenable Nessus Multiple Vulnerabilities (tns-2018-14)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107358");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-0732", "CVE-2018-0737");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-10-30 16:07:49 +0100 (Tue, 30 Oct 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Tenable Nessus Multiple Vulnerabilities(tns-2018-14)");

  script_tag(name:"summary", value:"This host is running Nessus and is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Tenable Nessus contains a flaw in the bundled third-party component OpenSSL library's key handling during a TLS handshake that causes a denial of service vulnerability due to key handling during a TLS handshake. (CVE-2018-0732)

Additionally a flaw in the library's RSA Key generation algorithm of OpenSSL allows a cache timing side channel attack to recover the private key. (CVE-2018-0737)");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers potentially to conduct denial-of-service or gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Nessus versions prior to version 8.0.0.");

  script_tag(name:"solution", value:"Upgrade to nessus version 8.0.0 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.tenable.com");
  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2018-14");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_nessus_web_server_detect.nasl");
  script_mandatory_keys("nessus/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!nesPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:nesPort, exit_no_version:TRUE)) exit(0);

nesVer = infos['version'];
path = infos['location'];

if(version_is_less(version:nesVer, test_version:"8.0.0"))
{
  report = report_fixed_ver(installed_version:nesVer, fixed_version:"8.0.0", install_path:path);
  security_message(data:report, port:nesPort);
  exit(0);
}
exit(99);
