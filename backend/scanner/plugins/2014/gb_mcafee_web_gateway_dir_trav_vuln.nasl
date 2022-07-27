###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_web_gateway_dir_trav_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# McAfee Web Gateway Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:mcafee:web_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804420");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-2535");
  script_bugtraq_id(66193);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-08 13:16:45 +0530 (Tue, 08 Apr 2014)");
  script_name("McAfee Web Gateway Directory Traversal Vulnerability");


  script_tag(name:"summary", value:"This host is running McAfee Web Gateway and is prone to directory traversal
vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to an error within the MWG web filtering port when processing
requests.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to disclose potentially sensitive
information.");
  script_tag(name:"affected", value:"McAfee Web Gateway 7.4.x before 7.4.1, 7.3.x before 7.3.2.6, 7.2.0.9 and earlier");
  script_tag(name:"solution", value:"Upgrade to McAfee Web Gateway 7.3.2.6 or 7.4.1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56958");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/91772");
  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10063");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_mcafee_web_gateway_detect.nasl");
  script_mandatory_keys("McAfee/Web/Gateway/installed");
  script_require_ports("Services/www", 8080);
  script_xref(name:"URL", value:"http://www.mcafee.com/us/products/web-gateway.aspx");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!mwgPort = get_app_port(cpe:CPE)){
  exit(0);
}

mwgVer = get_app_version(cpe:CPE, port:mwgPort);
if(!mwgVer){
  exit(0);
}

if(version_is_less(version:mwgVer, test_version:"7.2.0.10"))
{
  security_message(port:mwgPort);
  exit(0);
}

if(mwgVer =~ "^7\.4")
{
  if(version_is_less(version:mwgVer, test_version:"7.4.1"))
  {
    security_message(port:mwgPort);
    exit(0);
  }
}

if(mwgVer =~ "^7\.3")
{
  if(version_is_less(version:mwgVer, test_version:"7.3.2.6"))
  {
    security_message(port:mwgPort);
    exit(0);
  }
}
