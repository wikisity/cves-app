import React, { useState } from "react"
import axios from "axios"


function App() { 
  const [data, setData] = useState([])
  const [userInput, setUserInput] = useState('')

  const findCves =  async (event) => {
    if (userInput.length > 10 && userInput.toLowerCase().includes('cve')){
      await axios.get(`/Stage/cve?Id=${userInput}`).then((response) => {
        setData(response.data)
        console.log(response.data)
      })

    } else if (userInput.toLowerCase().includes(';') 
      && (userInput.toLowerCase().includes('low') 
    || userInput.toLowerCase().includes('medium') 
    || userInput.toLowerCase().includes('high') 
    || userInput.toLowerCase().includes('critical'))){
      let listItem = userInput.split(";")
      await axios.get(`/Stage/dateSev?pubStartDate=${listItem[0]}&pubEndDate=${listItem[1]}&severity=${listItem[2]}`).then((response) => {
        setData(response.data)
        console.log(response.data)
      })

    } else if (userInput.toLowerCase().includes(';')){
      let listItem = userInput.split(";")
      await axios.get(`/Stage/dateRange?pubStartDate=${listItem[0]}&pubEndDate=${listItem[1]}`).then((response) => {
        setData(response.data)
        console.log(response.data)
      })

    } else if (userInput.toLowerCase().includes('low') ||
        userInput.toLowerCase().includes('medium') 
        || userInput.toLowerCase().includes('high') 
        || userInput.toLowerCase().includes('critical')) {
          await axios.get(`/Stage/cves?severity=${userInput}`).then((response) => {
            setData(response.data)
            console.log(response.data)
      })
    } 

    setUserInput('')
    event.preventDefault()
  }
  
  return (
    <div className="app">
      <div className="title">
        <h2>Common Vulnerabilities and Exposures (CVEs) App</h2>
      </div>
      
      <div className="search">
        <input 
        value={userInput}
        onChange={event => setUserInput(event.target.value)}
        placeholder="Search for CVEs"
        onKeyPress={findCves}
        type="text"/>
      </div>

      <div className="container">

        <div className="top">
          {
            (userInput && data) ? 
            <table>
                <thead>
                  <tr>
                    <th className="id">ID</th>
                    <th>Attack Complexity</th>
                    <th>Attack Vector</th>
                    <th>Base Severity</th>
                    <th className="td-descp">Description</th>
                    <th className="td-date">Published Date</th>
                  </tr>
                </thead>
                <tbody>
                  {
                    data.map((item, index) => {
                      return <tr key={index}>
                        <td>{item.Id || item.id}</td>
                        <td className="td-attcomp">{item.attackComplexity}</td>
                        <td>{item.attackVector}</td>
                        <td>{item.baseSeverity}</td>
                        <td className="td-descp">{item.description}</td>
                        <td className="td-date">{item.published}</td>
                      </tr>
                    })
                  }
                </tbody>
              </table> : null
          }
        </div>
      </div>
    </div>
  );

}

export default App;
