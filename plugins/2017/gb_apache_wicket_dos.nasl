##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_wicket_dos.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# Apache Wicket Denial-of-Service Vulnerability
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

CPE = "cpe:/a:apache:wicket";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107117");
  script_version("$Revision: 14175 $");
  script_cve_id("CVE-2016-6793");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-01-02 13:26:09 +0100 (Mon, 02 Jan 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Wicket Denial-of-Service Vulnerability");

  script_tag(name:"summary", value:"This host is running Apache Wicket and is
  prone to a denial-of-service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Depending on the ISerializer set in the
  Wicket application, it's possible that a Wicket object deserialized from
  an untrusted source and utilized by the application causes the code to
  enter an infinite loop.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the application to enter an infinite loop and consume excessive CPU resources,
  resulting in denial-of-service conditions.");

  script_tag(name:"affected", value:"Apache Wicket versions 6.x and 1.5.x are vulnerable.");

  script_tag(name:"solution", value:"Update to 1.5.17 or 6.25.0.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95168");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_wicket_detect.nasl");
  script_mandatory_keys("Apache/Wicket/Installed");
  script_require_ports("Services/www", 8080);
  script_xref(name:"URL", value:"http://wicket.apache.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Port = get_app_port(cpe:CPE))
  exit(0);

if(!Ver = get_app_version(cpe:CPE, port:Port))
  exit(0);

if(version_in_range(version:Ver, test_version:"1.5.0", test_version2:"1.5.16"))
{
  fix = "1.5.17";
  VULN = TRUE ;
}
else if(version_in_range(version:Ver, test_version:"6.0", test_version2:"6.24.0"))
{
  fix = "6.25.0";
  VULN = TRUE ;
}


if(VULN)
{
  report = report_fixed_ver(installed_version:Ver, fixed_version:fix);
  security_message(data:report, port:Port);
  exit(0);
}

exit(99);
