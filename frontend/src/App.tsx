import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { HomePage } from './pages/HomePage';
import { ResultsPage } from './pages/ResultsPage';
import './index.css';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/scan/:id" element={<ResultsPage />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
