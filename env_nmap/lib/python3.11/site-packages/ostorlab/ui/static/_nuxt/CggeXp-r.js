var S=Object.defineProperty;var w=(i,e,a)=>e in i?S(i,e,{enumerable:!0,configurable:!0,writable:!0,value:a}):i[e]=a;var m=(i,e,a)=>w(i,typeof e!="symbol"?e+"":e,a);import{R as I,g as u}from"./BvH6OxSR.js";class g{constructor(e={}){this.t=e,this.g=new(typeof TextDecoder<"u"?TextDecoder:require("util").TextDecoder)}decode(e){const a=new Uint8Array(e),t=new DataView(a.buffer);return this.D={array:a,view:t},this.S=0,this.C()}C(e=this.m(!1)){switch(e){case"Z":return null;case"N":return;case"T":return!0;case"F":return!1;case"i":return this.F(({view:a},t)=>a.getInt8(t),1);case"U":return this.F(({view:a},t)=>a.getUint8(t),1);case"I":return this.F(({view:a},t)=>a.getInt16(t),2);case"l":return this.F(({view:a},t)=>a.getInt32(t),4);case"L":return this.N(8,this.t.int64Handling,!0);case"d":return this.F(({view:a},t)=>a.getFloat32(t),4);case"D":return this.F(({view:a},t)=>a.getFloat64(t),8);case"H":return this.N(this.V(),this.t.highPrecisionNumberHandling,!1);case"C":return String.fromCharCode(this.C("i"));case"S":return this.j(this.V());case"[":return this.M();case"{":return this.O()}throw Error("Unexpected type")}Z(){let e,a;switch(this.m(!0)){case"$":if(this.q(),e=this.m(!1),this.m(!0)!=="#")throw Error("Expected count marker");case"#":this.q(),a=this.V()}return{type:e,count:a}}M(){const{type:e,count:a}=this.Z();if("ZTF".indexOf(e)!==-1)return Array(a).fill(this.C(e));if(this.t.useTypedArrays)switch(e){case"i":return this.B(a);case"U":return this.L(a);case"I":return Int16Array.from({length:a},()=>this.C(e));case"l":return Int32Array.from({length:a},()=>this.C(e));case"d":return Float32Array.from({length:a},()=>this.C(e));case"D":return Float64Array.from({length:a},()=>this.C(e))}if(a!=null){const t=Array(a);for(let r=0;r<a;r++)t[r]=this.C(e);return t}{const t=[];for(;this.m(!0)!=="]";)t.push(this.C());return this.q(),t}}O(){const{type:e,count:a}=this.Z(),t={};if(a!=null)for(let r=0;r<a;r++)t[this.C("S")]=this.C(e);else{for(;this.m(!0)!=="}";)t[this.C("S")]=this.C();this.q()}return t}V(){const e=this.C();if(Number.isInteger(e)&&e>=0)return e;throw Error("Invalid length/count")}N(e,a,t){if(typeof a=="function")return this.F(a,e);switch(a){case"skip":return void this.q(e);case"raw":return t?this.L(e):this.j(e)}throw Error("Unsuported type")}L(e){return this.F(({array:a},t)=>new Uint8Array(a.buffer,t,e),e)}B(e){return this.F(({array:a},t)=>new Int8Array(a.buffer,t,e),e)}j(e){return this.F(({array:a},t)=>this.g.decode(new DataView(a.buffer,t,e)),e)}q(e=1){this.R(e),this.S+=e}m(e){const{array:a,view:t}=this.D;let r="N";for(;r==="N"&&this.S<a.byteLength;)r=String.fromCharCode(t.getInt8(this.S++));return e&&this.S--,r}F(e,a){this.R(a);const t=e(this.D,this.S,a);return this.S+=a,t}R(e){if(this.S+e>this.D.array.byteLength)throw Error("Unexpected EOF")}}function A(i,e){return new g(e).decode(i)}class b{downloadArrayBuffer(e,a){const t=new Blob([new Uint8Array(a).buffer]),r=window.URL.createObjectURL(t),n=document.createElement("a");n.href=r,n.download=e,document.body.appendChild(n),n.click(),n.remove(),window.URL.revokeObjectURL(r)}}const T=u`query scans($scanIds: [Int], $page: Int, $numberElements: Int, $orderBy: OxoScanOrderByEnum, $sort: SortEnum) {
  scans(scanIds: $scanIds, page: $page, numberElements: $numberElements, orderBy: $orderBy, sort: $sort) {
    pageInfo {
      count
      numPages
    }
    scans {
      id
      title
      createdTime
      progress
      assets {
        __typename
        ... on OxoAndroidFileAssetType {
          id
          packageName
          path
        }
        ... on OxoIOSFileAssetType {
          id
          bundleId
          path
        }
        ... on OxoAndroidStoreAssetType {
          id
          packageName
          applicationName
        }
        ... on OxoIOSStoreAssetType {
          id
          bundleId
          applicationName
        }
        ... on OxoUrlsAssetType {
          id
          links {
            url
            method
          }
        }
        ... on OxoNetworkAssetType {
          id
          networks {
            host
            mask
          }
        }
        ... on OxoDomainNameAssetsType {
          id
          domainNames {
            name
          }
        }
      }
    }
  }
}
`,N=u`
query Scan($scanId: Int!) {
  scan(scanId: $scanId) {
      id
      title
      createdTime
      messageStatus
      progress
  }
}
`,C=u`mutation DeleteScans ($scanIds: [Int]!){
  deleteScans (scanIds: $scanIds) {
    result
  }
}
`,O=u`mutation stopScans($scanIds: [Int]!) {
  stopScans(scanIds: $scanIds) {
    scans {
      id
    }
  }
}`,$=u`mutation ImportScan($file: Upload!, $scanId: Int) {
  importScan(file: $file, scanId: $scanId) {
    message
  }
}`,v=u`
  mutation RunScan ($scan: OxoAgentScanInputType!) {
    runScan (scan: $scan) {
      scan {
        id
      }
    }
  }
`,E=u`
  mutation ExportScan($scanId: Int!) {
    exportScan(scanId: $scanId) {
      content
    }
  }
`;class q{constructor(e){m(this,"requestor");m(this,"totalScans");this.requestor=new I(e),this.totalScans=0}async getScans(e,a){var n,o,s,c,d;a={...a},a.numberElements===-1&&(a.numberElements=void 0,a.page=void 0);const t=await this.requestor.post(e,{query:T,variables:a}),r=((n=t==null?void 0:t.data)==null?void 0:n.data.scans.scans)||[];return this.totalScans=((d=(c=(s=(o=t==null?void 0:t.data)==null?void 0:o.data)==null?void 0:s.scans)==null?void 0:c.pageInfo)==null?void 0:d.count)||r.length,r}async getScan(e,a){var r,n;const t=await this.requestor.post(e,{query:N,variables:{scanId:a}});return((n=(r=t==null?void 0:t.data)==null?void 0:r.data)==null?void 0:n.scan)||{}}async stopScans(e,a){var r,n;const t=await this.requestor.post(e,{query:O,variables:{scanIds:a}});return((n=(r=t==null?void 0:t.data)==null?void 0:r.stopScan)==null?void 0:n.result)||!1}async deleteScans(e,a){var r,n;const t=await this.requestor.post(e,{query:C,variables:{scanIds:a}});return((n=(r=t==null?void 0:t.data)==null?void 0:r.deleteScans)==null?void 0:n.result)||!1}async exportScan(e,a){var o,s;const t=await this.requestor.$axios.post(e.endpoint,{query:E,variables:{scanId:a}},{responseType:"arraybuffer",headers:{Accept:"application/ubjson","X-Api-Key":e.apiKey}}),r=A(t==null?void 0:t.data),n=(s=(o=r==null?void 0:r.data)==null?void 0:o.exportScan)==null?void 0:s.content;n!=null&&new b().downloadArrayBuffer("exported_scan.zip",n)}async importScan(e,a,t){var c,d,h,l,p;const r=new FormData,n=$,o={scanId:t,file:null};r.append("operations",JSON.stringify({query:n,variables:o,app:a,maps:{app:["variables.file"]}})),r.append("0",a),r.append("map",JSON.stringify({0:["variables.file"]}));const s=await this.requestor.$axios.post(e.endpoint,r,{headers:{"Content-Type":"multipart/form-data","X-Api-Key":e.apiKey}});if((((c=s==null?void 0:s.data)==null?void 0:c.errors)||[]).length>0)throw new Error((h=(d=s==null?void 0:s.data)==null?void 0:d.errors[0])==null?void 0:h.message);return((p=(l=s==null?void 0:s.data)==null?void 0:l.importScan)==null?void 0:p.result)||!1}async runScan(e,a){var r,n,o,s,c,d,h,l,p,f,y;const t=await this.requestor.post(e,{query:v,variables:{scan:a}});if((((r=t==null?void 0:t.data)==null?void 0:r.errors)||[]).length>0)throw new Error((o=(n=t==null?void 0:t.data)==null?void 0:n.errors[0])==null?void 0:o.message);if(((c=(s=t==null?void 0:t.data)==null?void 0:s.data)==null?void 0:c.runScan)===null||((h=(d=t==null?void 0:t.data)==null?void 0:d.data)==null?void 0:h.runScan)===void 0)throw new Error("An error occurred while creating the scan");return(y=(f=(p=(l=t==null?void 0:t.data)==null?void 0:l.data)==null?void 0:p.runScan)==null?void 0:f.scan)==null?void 0:y.id}}export{q as S};
