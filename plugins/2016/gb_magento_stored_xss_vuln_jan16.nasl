###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_magento_stored_xss_vuln_jan16.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Magento Stored Cross-Site Scripting Vulnerability - Jan16
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = 'cpe:/a:magentocommerce:magento';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806672");
  script_version("$Revision: 12096 $");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-01-28 18:09:47 +0530 (Thu, 28 Jan 2016)");
  script_name("Magento Stored Cross-Site Scripting Vulnerability - Jan16");

  script_tag(name:"summary", value:"This host is installed with magento and is
  prone to stored cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the
  app/design/adminhtml/default/default/template/sales/order/view/info.phtml script
  where email address given by user is not validated before using it in backend.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to take over affected site, create new administrator accounts,
  steal client information and do anything a legitimate administrator account can
  do.");

  script_tag(name:"affected", value:"Magento Community Edition (CE) versions before
  1.9.2.3 and Magento Enterprise Edition (EE) versions before 1.14.2.3");

  script_tag(name:"solution", value:"Upgrade to Magento Community Edition (CE)
  1.9.2.3 or later, or upgrade to Magento Enterprise Edition 1.14.2.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://magento.com/security/patches/supee-7405");
  script_xref(name:"URL", value:"https://blog.sucuri.net/2016/01/security-advisory-stored-xss-in-magento.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!magPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!magVer = get_app_version(cpe:CPE, port:magPort)){
  exit(0);
}

##If no Edition Information available test for CE only

if(!EE = get_kb_item("magento/EE/installed")){
  CE = get_kb_item("magento/CE/installed");
}


##For Enterprise Edition < 1.14.2.3 are vulnerable
if(EE)
{
  if(version_is_less(version:magVer, test_version:"1.14.2.3"))
  {
    report = report_fixed_ver(installed_version:magVer, fixed_version:'1.14.2.3');
    security_message(port:magPort, data:report);
    exit(0);
  }
}

##For Community Edition <1.9.2.3 are vulnerable
##If no Edition Information available test for CE only
else
{
  if(version_is_less(version:magVer, test_version:"1.9.2.3"))
  {
    report = report_fixed_ver(installed_version:magVer, fixed_version:'1.9.2.3');
    security_message(port:magPort, data:report);
    exit(0);
  }
}
exit(99);
