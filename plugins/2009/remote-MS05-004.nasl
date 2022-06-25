# OpenVAS Vulnerability Test
# $Id: remote-MS05-004.nasl 14335 2019-03-19 14:46:57Z asteins $
# Description:
# Microsoft Security Bulletin MS05-004
# ASP.NET Path Validation Vulnerability
#
# Affected Software:
#
# Microsoft .NET Framework 1.0
# or Windows Server 2003 with SP2 for Itanium-based Systems
#
# Windows Vista
# or Windows Server 2003 with SP2 for Itanium-based Systems
#
# Microsoft .NET Framework 1.1
# or Windows Server 2003 with SP2 for Itanium-based Systems
#
# Windows Vista
# or Windows Server 2003 with SP2 for Itanium-based Systems
#
# Non-Affected Software:
# None
#
# Affected Components:
# ASP.NET
#
# remote-MS05-004.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101010");
  script_version("$Revision: 14335 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:46:57 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-03-15 22:16:07 +0100 (Sun, 15 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(11342);
  script_cve_id("CVE-2004-0847");
  script_name("Microsoft Security Bulletin MS05-004");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);

  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("find_service.nasl", "remote-detect-MSdotNET-version.nasl");
  script_require_ports("Services/www");
  script_mandatory_keys("dotNET/version", "dotNET/port");

  script_tag(name:"solution", value:"Microsoft has released a patch to correct this issue,
you can download it from the references.");
  script_tag(name:"summary", value:"A canonicalization vulnerability exists in ASP.NET that could allow an attacker to bypass the security of an ASP.NET Web site
and gain unauthorized access. An attacker who successfully exploited this vulnerability could take a variety of actions,
depending on the specific contents of the website.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS05-004.mspx");

  exit(0);

}


dotnet = get_kb_item("dotNET/version");
port = get_kb_item("dotNET/port");

if(!dotnet)
	exit(0);

else
{
	dotnetversion['1.0'] = revcomp(a:dotnet, b:"1.0.3705.6021");
	dotnetversion['1.1'] = revcomp(a:dotnet, b:"1.1.4322.2037");

	foreach version (dotnetversion)
	{
   	if (version == -1){
      # Report 'Microsoft ASP.NET Path Validation Vulnerability (MS05-004)'
      report = 'Missing MS05-004 patch, detected Microsoft .Net Framework version: ' + dotnet;
			security_message(port:port, data:report);
      exit( 0 );
		}
	}
}

exit( 99 );
