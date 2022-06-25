###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atlassian_confluence_sec_bypass_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# Atlassian Confluence CVE-2017-9505 Security Bypass Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:atlassian:confluence";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107224");
  script_version("$Revision: 11874 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-19 17:36:44 +0200 (Mon, 19 Jun 2017)");
  script_cve_id("CVE-2017-9505");

  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Atlassian Confluence CVE-2017-9505 Security Bypass Vulnerability");

  script_tag(name:"summary", value:"Atlassian Confluence is prone to a security-bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  # Already covered in 2017/gb_atlassian_confluence_bypass_vuln.nasl
  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"insight", value:"The flaw is due to the watch functionality provided for the user to
  subscrite to specific content.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass certain security
  restrictions and perform unauthorized actions.");

  script_tag(name:"affected", value:"Atlassian Confluence 4.3.0 and later are vulnerable");
  script_tag(name:"solution", value:"Update to Atlassian Confluence 6.2.1.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Jun/17");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Web application abuses");

  script_dependencies("gb_atlassian_confluence_detect.nasl");
  script_mandatory_keys("atlassian_confluence/installed");
  script_require_ports("Services/www", 8080);

  exit(0);
}

exit(66);

include("host_details.inc");
include("version_func.inc");

if(!Port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!Ver = get_app_version(cpe:CPE, port:Port)){
  exit(0);
}

if((Ver =~ "4\.") || (Ver =~ "5\.") || (Ver =~ "6\.")){
  if(version_is_less(version: Ver, test_version:"6.2.1")){
    report = report_fixed_ver(installed_version:Ver, fixed_version:"6.2.1");
    security_message(port:Port, data:report);
    exit(0);
  }
}

exit(99);
