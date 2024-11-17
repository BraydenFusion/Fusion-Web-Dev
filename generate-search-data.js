const fs = require('fs');
const path = require('path');

const pages = [
  {
    id: 1,
    title: "Home - Fusion AI",
    url: "/index.html",
    content: "Welcome to Fusion AI. We provide cutting-edge artificial intelligence and automation solutions..."
  },
  {
    id: 2,
    title: "About Us - Fusion AI",
    url: "/about.html",
    content: "Learn more about Fusion AI, our mission, vision, and the team driving our innovative AI solutions..."
  },
  {
    id: 3,
    title: "Pricing - Fusion AI",
    url: "/pricing.html",
    content: "Explore our pricing plans designed to fit businesses of all sizes. Choose the best option for your needs..."
  },
  {
    id: 4,
    title: "Support - Fusion AI",
    url: "/support.html",
    content: "Access our support resources, FAQs, and contact information to get help when you need it..."
  }
  // Add more pages as needed
];

fs.writeFileSync(
  path.join(__dirname, 'search-data.json'),
  JSON.stringify(pages, null, 2)
);

console.log('search-data.json has been generated successfully.');