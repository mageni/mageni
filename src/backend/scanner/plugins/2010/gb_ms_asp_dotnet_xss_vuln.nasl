###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_asp_dotnet_xss_vuln.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# Microsoft ASP.NET Cross-Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801342");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)");
  script_cve_id("CVE-2010-2084");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Microsoft ASP.NET Cross-Site Scripting vulnerability");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/394300.php");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/cve/2010-2084");
  script_xref(name:"URL", value:"http://www.communities.hp.com/securitysoftware/blogs/spilabs/archive/2010/03/30/configuration-is-half-the-battle-asp-net-and-cross-site-scripting.aspx");

  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_dependencies("remote-detect-MSdotNET-version.nasl");
  script_mandatory_keys("dotNET/install", "aspNET/installed", "aspNET/version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to conduct
cross-site scripting attacks against the form control via vectors related to an
attribute.");
  script_tag(name:"affected", value:"Microsoft ASP.NET version 2.0 and prior.");
  script_tag(name:"insight", value:"The flaw is due to error in the handling of
'HtmlContainerControl', which does not prevent setting the 'InnerHtml' property
on a control that inherits from HtmlContainerControl when processing the vectors
related to an attribute.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running Microsoft ASP .NET and is prone to
Cross-Site Scripting Vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

dotNet = get_kb_item("dotNET/install");
if(!dotNet){
  exit(0);
}

apsdotNet = get_kb_item("aspNET/installed");
if(!aspdotNet){
  exit(0);
}

aspdotnetVer = get_kb_item("aspNET/version");
if(!dotNet){
  exit(0);
}

if(version_is_less_equal(version:aspdotnetVer, test_version:"2.0")){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}
