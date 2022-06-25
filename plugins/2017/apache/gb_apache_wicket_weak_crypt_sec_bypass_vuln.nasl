###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_wicket_weak_crypt_sec_bypass_vuln.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Apache Wicket 'CryptoMapper' Cross Site Request Forgery Vulnerability
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

CPE = "cpe:/a:apache:wicket";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811841");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2014-7808");
  script_bugtraq_id(100946);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-04 13:06:12 +0530 (Wed, 04 Oct 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Wicket 'CryptoMapper' Cross Site Request Forgery Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Apache Wicket
  and is prone to cross site request forgery vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to Wicket's default security
  settings of the usage of CryptoMapper to encrypt/obfuscate pages urls, which is not
  strong enough. It is possible to predict the encrypted version of an url based on
  the previous history.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to defeat a cryptographic protection mechanism and predict encrypted URLs by
  leveraging use of CryptoMapper as the default encryption provider.");

  script_tag(name:"affected", value:"Apache Wicket versions before 1.5.13, 6.x before
  6.19.0, and 7.x before 7.0.0-M5.");

  script_tag(name:"solution", value:"Upgrade to Apache Wicket 1.5.13 or 6.19.0
  or 7.0.0-M5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.smrrd.de/cve-2014-7808-apache-wicket-csrf-2014.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_apache_wicket_detect.nasl");
  script_mandatory_keys("Apache/Wicket/Installed");
  script_require_ports("Services/www", 8080);
  script_xref(name:"URL", value:"http://wicket.apache.org");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

if(!Port = get_app_port(cpe:CPE)){
  exit(0);
}

Ver = get_app_version(cpe:CPE, port:Port);
if(!Ver){
  exit(0);
}

if(version_is_less(version:Ver, test_version:"1.5.13")){
  fix = "1.5.13";
}

else if(Ver =~ "^(6\.)")
{
  if(version_is_less(version:Ver, test_version:"6.19.0")){
    fix = "6.19.0";
  }
}

else if(Ver =~ "^(7\.)" && revcomp(a: Ver, b: "7.0.0.M5") < 0){
  fix = "7.0.0-M5";
}

if(fix)
{
  report = report_fixed_ver(installed_version:Ver, fixed_version:fix);
  security_message(data:report, port:Port);
  exit(0);
}
exit(0);
