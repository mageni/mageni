###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-MS06-056.nasl 9333 2018-04-05 13:19:07Z cfischer $
#
# Microsoft Security Bulletin MS06-056
# .NET Framework 2.0 Cross-Site Scripting Vulnerability - CVE-2006-3436
#
# Affected Software:
#
# .NET Framework 2.0 for the following operating system versions:
# Microsoft Windows 2000 Service Pack 4
# Microsoft Windows XP Service Pack 1 or Windows XP Service Pack 2
# Microsoft Windows XP Professional x64 Edition
# Microsoft Windows XP Tablet PC Edition
# Microsoft Windows XP Media Center Edition
# Microsoft Windows Server 2003 or Windows Server 2003 Service Pack 1
# Microsoft Windows Server with SP1 for Itanium-based Systems
# Microsoft Windows Server 2003 x64 Edition
#
# Non-Affected Software:
#
# Microsoft Windows Server 2003 for Itanium-based Systems
#
# Tested Microsoft Windows Components:
#
# Affected Components:
#
# Microsoft .NET Framework 2.0
#
# Non-Affected Components:
#
# Microsoft .NET Framework 1.0
# Microsoft .NET Framework 1.1
#
# remote-MS06-056.nasl
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101006");
  script_version("$Revision: 9333 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-05 15:19:07 +0200 (Thu, 05 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-15 21:21:09 +0100 (Sun, 15 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_bugtraq_id(20337);
  script_cve_id("CVE-2006-3436");
  script_name("Microsoft Security Bulletin MS06-056");
  script_category(ACT_GATHER_INFO);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("find_service.nasl", "remote-detect-MSdotNET-version.nasl");
  script_mandatory_keys("dotNET/version");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS06-056.mspx");

  script_tag(name:"solution", value:"Microsoft has released an update to correct this issue,
  please see the reference for more information.");

  script_tag(name:"summary", value:"A cross-site scripting vulnerability exists in a server
  running a vulnerable version of the .Net Framework 2.0 that could inject a client side
  script in the user's browser.");

  script_tag(name:"impact", value:"The script could spoof content, disclose information,
  or take any action that the user could take on the affected web site.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");

dotnet = get_kb_item( "dotNET/version" );
if( ! dotnet ) exit( 0 );
port = get_kb_item( "dotNET/port" );

# Microsoft .NET Framework version 2.0
if( revcomp( a:dotnet, b:"2.0.50727.210" ) == -1 ) {
  # Report 'Microsoft .NET Framework 2.0 Cross-Site Scripting Vulnerability (MS06-056)'
  report = 'Missing MS06-056 patch, detected Microsoft .Net Framework version: ' + dotnet;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );