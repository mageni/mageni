###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntopng_priv_esc.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# ntopng Privilege Escalation Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ntop:ntopng";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107110");
  script_version("$Revision: 12051 $");
  script_cve_id("CVE-2015-8368");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-20 06:40:16 +0200 (Tue, 20 Dec 2016)");
  script_name("ntopng Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"The host is installed with ntopng and is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  local users to gain extra privileges.");

  script_tag(name:"affected", value:"ntopng 2.0.151021 and below");

  script_tag(name:"solution", value:"Upgrade to ntopng 2.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38836/");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_ntopng_detect.nasl");
  script_mandatory_keys("ntopng/installed");
  script_require_ports("Services/www", 3000);

  script_xref(name:"URL", value:"http://www.ntop.org/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ntopngVer = get_app_version(cpe:CPE, port: appPort)){
  exit(0);
}

if(version_is_less(version:ntopngVer, test_version:"2.2"))
{
    report = report_fixed_ver(installed_version:ntopngVer, fixed_version:"2.2");
    security_message(data:report, port:appPort);
    exit(0);
}

exit(99);
