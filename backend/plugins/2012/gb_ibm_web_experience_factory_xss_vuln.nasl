###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_web_experience_factory_xss_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# IBM Web Experience Factory Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802563");
  script_version("$Revision: 11857 $");
  script_bugtraq_id(51246);
  script_cve_id("CVE-2011-5048");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-01-19 18:01:09 +0530 (Thu, 19 Jan 2012)");
  script_name("IBM Web Experience Factory Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51246/info");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21575083");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaws are due to improper validation of user-supplied input to
  'INPUT' and 'TEXTAREA' elements.");
  script_tag(name:"solution", value:"Upgrade to the IBM Web Experience Factory 7.0.1.2 or later.");
  script_tag(name:"summary", value:"This host is installed with IBM Web Experience Factory and is prone
  to multiple cross site scripting vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected
  site.");
  script_tag(name:"affected", value:"IBM Web Experience Factory version 7.0 and 7.0.1");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www14.software.ibm.com/webapp/download/home.jsp");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IBM WebSphere Portlet Factory";
if(!registry_key_exists(key:key)){
  exit(0);
}

ibmName = registry_get_sz(key:key, item:"DisplayName");
if("IBM WebSphere Portlet Factory" >< ibmName)
{
  ibmVer = registry_get_sz(key:key + item, item:"DisplayVersion");

  if(ibmVer != NULL)
  {
    if(version_in_range(version:ibmVer, test_version:"7.0", test_version2:"7.0.1.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" ) ;
    }
  }
}
