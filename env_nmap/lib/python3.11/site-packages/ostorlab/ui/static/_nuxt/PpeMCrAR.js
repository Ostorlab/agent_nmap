var p=Object.defineProperty;var l=(o,e,r)=>e in o?p(o,e,{enumerable:!0,configurable:!0,writable:!0,value:r}):o[e]=r;var i=(o,e,r)=>l(o,typeof e!="symbol"?e+"":e,r);import{R as A,g as d}from"./BvH6OxSR.js";const c=d`
query AgentGroups ($assetType: AssetTypeEnum) {
  agentGroups (assetType: $assetType) {
    agentGroups {
      key
      id
      name
      description
      yamlSource
    }
  }
}
`,y=d`
mutation PublishAgentGroup ($agentGroup: OxoAgentGroupCreateInputType!) {
    publishAgentGroup (agentGroup: $agentGroup) {
      agentGroup {
        id
        name
        description
        key
      }
    }
  }
`,T=d`mutation DeleteAgentGroup ($agentGroupId: Int!){
            deleteAgentGroup (agentGroupId: $agentGroupId) {
                result
            }
        }`;class m{constructor(e){i(this,"requestHandler");this.requestHandler=new A(e)}async getAgentGroups(e,r){var a,u,n,s,g,G;const t=await this.requestHandler.post(e,{query:c,variables:{assetType:r}});if((((a=t==null?void 0:t.data)==null?void 0:a.errors)||[]).length>0)throw new Error((n=(u=t==null?void 0:t.data)==null?void 0:u.errors[0])==null?void 0:n.message);return((G=(g=(s=t==null?void 0:t.data)==null?void 0:s.data)==null?void 0:g.agentGroups)==null?void 0:G.agentGroups)||[]}async createAgentGroup({scanner:e,agentGroup:r}){var a,u,n,s,g,G;const t=await this.requestHandler.post(e,{query:y,variables:{agentGroup:r}});if((((a=t==null?void 0:t.data)==null?void 0:a.errors)||[]).length>0)throw new Error((n=(u=t==null?void 0:t.data)==null?void 0:u.errors[0])==null?void 0:n.message);return(G=(g=(s=t==null?void 0:t.data)==null?void 0:s.data)==null?void 0:g.publishAgentGroup)==null?void 0:G.agentGroup}async deleteAgentGroup(e,r){var a,u,n;const t=await this.requestHandler.post(e,{query:T,variables:{agentGroupId:r}});if((((a=t==null?void 0:t.data)==null?void 0:a.errors)||[]).length>0)throw new Error((n=(u=t==null?void 0:t.data)==null?void 0:u.errors[0])==null?void 0:n.message)}}export{m as A};
